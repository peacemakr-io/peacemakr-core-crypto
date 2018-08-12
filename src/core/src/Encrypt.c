//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <crypto.h>

#include <CiphertextBlob.h>
#include <EVPHelper.h>
#include <Key.h>

#include <openssl/evp.h>
#include <stdbool.h>

static void digest_message(const unsigned char *message, size_t message_len,
                           const EVP_MD *digest_algo, buffer_t *digest) {
  EVP_MD_CTX *mdctx;

  if ((mdctx = EVP_MD_CTX_create()) == NULL) {
    PEACEMAKR_ERROR("mdctx_create failed");
    return;
  }

  if (1 != EVP_DigestInit_ex(mdctx, digest_algo, NULL)) {
    PEACEMAKR_ERROR("digestinit_ex failed");
    return;
  }

  if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
    PEACEMAKR_ERROR("digestupdate failed");
    return;
  }

  size_t digest_len = Buffer_get_size(digest);
  unsigned char digest_buf[digest_len];
  if (1 != EVP_DigestFinal_ex(mdctx, digest_buf, NULL)) {
    PEACEMAKR_ERROR("digestfinal_ex failed");
    return;
  }
  Buffer_set_bytes(digest, digest_buf, digest_len);

  EVP_MD_CTX_destroy(mdctx);
}

static bool symmetric_encrypt(const EVP_CIPHER *cipher,
                              const EVP_MD *digest_algo, ciphertext_blob_t *out,
                              const buffer_t *key,
                              const unsigned char *plaintext,
                              size_t plaintext_len, const unsigned char *aad,
                              size_t aad_len) {

  EVP_CIPHER_CTX *ctx;
  int len = 0;
  size_t ciphertext_len = 0;

  const buffer_t *iv = CiphertextBlob_get_iv(out);
  buffer_t *tag = CiphertextBlob_mutable_tag(out);

  // Store the message digest
  digest_message(plaintext, plaintext_len, digest_algo,
                 CiphertextBlob_mutable_digest(out));

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    PEACEMAKR_ERROR("cipher ctx init failed");
    return false;
  }

  /* Initialize the encryption */
  if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, Buffer_get_bytes(key, NULL),
                              Buffer_get_bytes(iv, NULL))) {
    PEACEMAKR_ERROR("encryptinit_ex failed");
    return false;
  }

  /* Handle any AAD */
  if (aad != NULL && aad_len > 0) {
    if (aad_len > INT_MAX) {
      for (int i = 0; i < aad_len; i += (INT_MAX >> 1)) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad + i, (INT_MAX >> 1))) {
          PEACEMAKR_ERROR("encryptupdate failed on aad, chunk %d of %d", i,
                          aad_len / (INT_MAX >> 1));
          return false;
        }
      }
    } else {
      if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len)) {
        PEACEMAKR_ERROR("encryptupdate failed on aad");
        return false;
      }
    }

    // Set the AAD in the CiphertextBlob
    Buffer_set_bytes(CiphertextBlob_mutable_aad(out), aad, aad_len);
  }

  /* Now set up to do the actual encryption */
  unsigned char ciphertext[Buffer_get_size(CiphertextBlob_mutable_ciphertext(out))];

  if (plaintext == NULL || plaintext_len == 0) {
    PEACEMAKR_ERROR("cannot encrypt an empty string");
    return false;
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (plaintext_len > INT_MAX) {
    unsigned char *ciphertext_ptr = &ciphertext[0];
    for (int i = 0; i < plaintext_len; i += (INT_MAX >> 1)) {
      if (1 != EVP_EncryptUpdate(ctx, ciphertext_ptr, &len, plaintext + i,
                                 (INT_MAX >> 1))) {
        PEACEMAKR_ERROR("encryptupdate failed, chunk %d of %d", i,
                        plaintext_len / (INT_MAX >> 1));
        return false;
      }
      ciphertext_len += len;
      ciphertext_ptr += len;
    }
  } else {
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                               (int)plaintext_len)) {
      PEACEMAKR_ERROR("encryptupdate failed");
      return false;
    }
    ciphertext_len = (size_t)len;
  }

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    PEACEMAKR_ERROR("encryptfinal_ex failed");
    return false;
  }
  ciphertext_len += len;
  Buffer_set_bytes(CiphertextBlob_mutable_ciphertext(out), ciphertext,
                   ciphertext_len);

  /* Get the tag at this point, if the algorithm provides one */
  size_t taglen = Buffer_get_size(tag);
  if (taglen > 0) {
    unsigned char tag_buf[taglen];

    if (1 !=
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen, tag_buf)) {
      PEACEMAKR_ERROR("getting the tag failed");
      return false;
    }
    Buffer_set_bytes(tag, tag_buf, taglen); // store the tag in the buffer
  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return true;
}

static bool asymmetric_encrypt(EVP_PKEY **pub_key, int num_pub_keys,
                               const EVP_CIPHER *cipher,
                               ciphertext_blob_t *ciphertext_blob,
                               const unsigned char *plaintext,
                               size_t plaintext_len) {
  EVP_CIPHER_CTX *ctx;

  int ciphertext_len = 0;

  int len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    PEACEMAKR_ERROR("cipher_ctx_new failed");
    return false;
  }

  unsigned char *encrypted_key_buf;
  size_t ivlen = Buffer_get_size(CiphertextBlob_get_iv(ciphertext_blob));
  unsigned char iv_buf[ivlen];
  buffer_t *mutable_ciphertext =
      CiphertextBlob_mutable_ciphertext(ciphertext_blob);
  unsigned char ciphertext_buf[Buffer_get_size(mutable_ciphertext)];

  /* Initialise the envelope seal operation. This operation generates
   * a key for the provided cipher, and then encrypts that key a number
   * of times (one for each public key provided in the pub_key array). In
   * this example the array size is just one. This operation also
   * generates an IV and places it in iv. */
  if (1 != EVP_SealInit(ctx, cipher, &encrypted_key_buf, NULL, iv_buf, pub_key,
                        num_pub_keys)) {
    PEACEMAKR_ERROR("sealinit failed");
    return false;
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_SealUpdate can be called multiple times if necessary
   */
  if (plaintext_len > INT_MAX) {
    for (int i = 0; i < plaintext_len; i += (INT_MAX >> 1)) {
      if (1 !=
          EVP_SealUpdate(ctx, ciphertext_buf, &len, plaintext + i, (INT_MAX >> 1))) {
        PEACEMAKR_ERROR("sealupdate failed, on batch %d of %d", i, plaintext_len / (INT_MAX >> 1));
        return false;
      }
      ciphertext_len += len;
    }
  }
  else {
    if (1 !=
        EVP_SealUpdate(ctx, ciphertext_buf, &len, plaintext, (int)plaintext_len)) {
      PEACEMAKR_ERROR("sealupdate failed");
      return false;
    }
    ciphertext_len += len;
  }

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_SealFinal(ctx, ciphertext_buf + len, &len)) {
    PEACEMAKR_ERROR("sealfinal failed");
    return false;
  }
  ciphertext_len += len;
  Buffer_set_bytes(mutable_ciphertext, ciphertext_buf, (size_t)ciphertext_len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return true;
}

ciphertext_blob_t *encrypt(crypto_config_t cfg, const peacemakr_key_t **key, int num_keys,
                           const plaintext_t *plain) {

  const EVP_CIPHER *cipher = parse_cipher(cfg);
  const int cipher_block_size = EVP_CIPHER_block_size(cipher);
  size_t iv_len = (size_t)EVP_CIPHER_iv_length(cipher);
  size_t tag_len = get_taglen(cfg);
  size_t aad_len = plain->aad_len;

  size_t ciphertext_len = plain->data_len + cipher_block_size - 1;
  if (plain->data_len > INT_MAX) {
    ciphertext_len =
        ((INT_MAX >> 1) + EVP_CIPHER_block_size(cipher) - 1) // max block size
        * ((plain->data_len / (INT_MAX >> 1)) +
           1); // number of blocks (rounded up)
  }

  size_t digest_len = get_digest_len(cfg);

  ciphertext_blob_t *out = CiphertextBlob_new(cfg, iv_len, tag_len, aad_len,
                                              ciphertext_len, digest_len);

  bool success = false;
  switch (cfg.mode) {
  case SYMMETRIC: {
    if (num_keys != 1) {
      PEACEMAKR_ERROR("only support single key for symmetric encryption");
      return NULL;
    }
    success = symmetric_encrypt(cipher, parse_digest(cfg), out,
                                PeacemakrKey_symmetric(key[0]), plain->data,
                                plain->data_len, plain->aad, plain->aad_len);
    break;
  }
  case ASYMMETRIC:
//    success = asymmetric_encrypt();
    break;
  }

  if (!success) {
    PEACEMAKR_ERROR("encryption failed");
    return NULL;
  }

  return out;
}

int decrypt(const peacemakr_key_t *key, const ciphertext_blob_t *cipher,
            plaintext_t *plain) {
  return 0; // TODO
}
