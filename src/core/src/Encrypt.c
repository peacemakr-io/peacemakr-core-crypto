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

#include <memory.h>
#include <openssl/evp.h>
#include <stdbool.h>

static bool symmetric_encrypt(const peacemakr_key_t *peacemakrkey,
                              ciphertext_blob_t *out,
                              const unsigned char *plaintext,
                              size_t plaintext_len, const unsigned char *aad,
                              size_t aad_len) {

  EVP_CIPHER_CTX *ctx;
  int len = 0;
  size_t ciphertext_len = 0;

  const EVP_CIPHER *cipher = parse_cipher(CiphertextBlob_symm_cipher(out));
  const buffer_t *key = PeacemakrKey_symmetric(peacemakrkey);

  const buffer_t *iv = CiphertextBlob_iv(out);
  buffer_t *tag = CiphertextBlob_mutable_tag(out);
  buffer_t *aad_buf = CiphertextBlob_mutable_aad(out);
  buffer_t *ciphertext_buf = CiphertextBlob_mutable_ciphertext(out);

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    PEACEMAKR_ERROR("cipher ctx init failed\n");
    return false;
  }

  /* Initialize the encryption */
  if (iv != NULL) {
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, Buffer_get_bytes(key, NULL),
                                Buffer_get_bytes(iv, NULL))) {
      PEACEMAKR_ERROR("encryptinit_ex failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  } else {
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, Buffer_get_bytes(key, NULL),
                                NULL)) {
      PEACEMAKR_ERROR("encryptinit_ex failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Handle any AAD */
  if (aad != NULL && aad_len > 0) {
    if (aad_len > INT_MAX) {
      for (int i = 0; i < aad_len; i += (INT_MAX >> 1)) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad + i, (INT_MAX >> 1))) {
          PEACEMAKR_ERROR("encryptupdate failed on aad, chunk %d of %d\n", i,
                          aad_len / (INT_MAX >> 1));
          EVP_CIPHER_CTX_free(ctx);
          return false;
        }
      }
    } else {
      if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len)) {
        PEACEMAKR_ERROR("encryptupdate failed on aad\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
    }

    // Set the AAD in the CiphertextBlob
    Buffer_set_bytes(aad_buf, aad, aad_len);
  }

  /* Now set up to do the actual encryption */
  unsigned char *ciphertext = alloca(Buffer_get_size(ciphertext_buf));

  if (plaintext == NULL || plaintext_len == 0) {
    PEACEMAKR_ERROR("cannot encrypt an empty string\n");
    EVP_CIPHER_CTX_free(ctx);
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
        PEACEMAKR_ERROR("encryptupdate failed, chunk %d of %d\n", i,
                        plaintext_len / (INT_MAX >> 1));
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      ciphertext_len += len;
      ciphertext_ptr += len;
    }
  } else {
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                               (int)plaintext_len)) {
      PEACEMAKR_ERROR("encryptupdate failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    ciphertext_len = (size_t)len;
  }

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    PEACEMAKR_ERROR("encryptfinal_ex failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len += len;
  Buffer_set_bytes(ciphertext_buf, ciphertext, ciphertext_len);

  /* Get the tag at this point, if the algorithm provides one */
  if (tag != NULL) {
    size_t taglen = Buffer_get_size(tag);
    if (taglen > 0) {
      unsigned char tag_buf[taglen];

      if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen,
                                   tag_buf)) {
        PEACEMAKR_ERROR("getting the tag failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      Buffer_set_bytes(tag, tag_buf, taglen); // store the tag in the buffer
    }
  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return true;
}

static bool symmetric_decrypt(const peacemakr_key_t *peacemakrkey,
                              const ciphertext_blob_t *in, buffer_t **plaintext,
                              buffer_t **aad) {
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  size_t plaintext_len = 0;

  const EVP_CIPHER *cipher = parse_cipher(CiphertextBlob_symm_cipher(in));
  const buffer_t *key = PeacemakrKey_symmetric(peacemakrkey);

  const buffer_t *ciphertext = CiphertextBlob_ciphertext(in);
  const unsigned char *ciphertext_buf = Buffer_get_bytes(ciphertext, NULL);
  const size_t ciphertext_len = Buffer_get_size(ciphertext);

  const buffer_t *stored_aad = CiphertextBlob_aad(in);
  const unsigned char *aad_buf = Buffer_get_bytes(stored_aad, NULL);
  const size_t aad_len = Buffer_get_size(stored_aad);

  const buffer_t *stored_tag = CiphertextBlob_tag(in);
  unsigned char *tag_buf = NULL;
  size_t taglen = 0;
  if (stored_tag != NULL) {
    tag_buf = (unsigned char *)Buffer_get_bytes(stored_tag, NULL);
    taglen = Buffer_get_size(stored_tag);
  }

  const buffer_t *iv = CiphertextBlob_iv(in);

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    PEACEMAKR_ERROR("cipher ctx init failed\n");
    return false;
  }

  /* Initialize the decryption */
  if (iv != NULL) {
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, Buffer_get_bytes(key, NULL),
                                Buffer_get_bytes(iv, NULL))) {
      PEACEMAKR_ERROR("encryptinit_ex failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  } else {
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, Buffer_get_bytes(key, NULL),
                                NULL)) {
      PEACEMAKR_ERROR("encryptinit_ex failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Handle any AAD */
  if (aad_buf != NULL && aad_len > 0) {
    if (aad_len > INT_MAX) {
      for (int i = 0; i < aad_len; i += (INT_MAX >> 1)) {
        if (1 !=
            EVP_DecryptUpdate(ctx, NULL, &len, aad_buf + i, (INT_MAX >> 1))) {
          PEACEMAKR_ERROR("encryptupdate failed on aad, chunk %d of %d\n", i,
                          aad_len / (INT_MAX >> 1));
          EVP_CIPHER_CTX_free(ctx);
          return false;
        }
      }
    } else {
      if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad_buf, (int)aad_len)) {
        PEACEMAKR_ERROR("encryptupdate failed on aad\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
    }
  }

  /* Now set up to do the actual decryption */
  unsigned char *plaintext_buf = alloca(ciphertext_len << 1);

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (ciphertext_len > INT_MAX) {
    unsigned char *plaintext_ptr = &plaintext_buf[0];
    for (int i = 0; i < ciphertext_len; i += (INT_MAX >> 1)) {
      if (1 != EVP_DecryptUpdate(ctx, plaintext_ptr, &len, ciphertext_buf + i,
                                 (INT_MAX >> 1))) {
        PEACEMAKR_ERROR("encryptupdate failed, chunk %d of %d\n", i,
                        ciphertext_len / (INT_MAX >> 1));
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      plaintext_len += len;
      plaintext_ptr += len;
    }
  } else {
    if (1 != EVP_DecryptUpdate(ctx, plaintext_buf, &len, ciphertext_buf,
                               (int)ciphertext_len)) {
      PEACEMAKR_ERROR("decryptupdate failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    plaintext_len = (size_t)len;
  }

  if (taglen > 0 && tag_buf != NULL) {
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                                 (void *)tag_buf)) {
      PEACEMAKR_ERROR("setting the tag failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Finalise the decryption. */
  int ret = EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0) {
    /* Success */
    plaintext_len += len;

    *plaintext = Buffer_new(plaintext_len);
    Buffer_set_bytes(*plaintext, plaintext_buf, plaintext_len);
    *aad = Buffer_new(aad_len);
    Buffer_set_bytes(*aad, aad_buf, aad_len);
    return true;
  } else {
    /* Verify failed */
    *plaintext = NULL;
    *aad = NULL;
    return false;
  }
}

static bool asymmetric_encrypt(const peacemakr_key_t *pub_key,
                               ciphertext_blob_t *out,
                               const unsigned char *plaintext,
                               size_t plaintext_len, const unsigned char *aad,
                               size_t aad_len) {
  EVP_CIPHER_CTX *ctx;
  size_t ciphertext_len = 0;
  int len = 0;

  const EVP_CIPHER *cipher = parse_cipher(CiphertextBlob_symm_cipher(out));

  EVP_PKEY *pkey = PeacemakrKey_asymmetric(pub_key);

  buffer_t *tag = CiphertextBlob_mutable_tag(out);

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    PEACEMAKR_ERROR("cipher_ctx_new failed\n");
    return false;
  }

  buffer_t *encrypted_key = CiphertextBlob_mutable_encrypted_key(out);
  size_t keylen = Buffer_get_size(encrypted_key);
  int encrypted_key_len = 0;
  unsigned char *encrypted_key_buf = alloca(keylen);

  size_t ivlen = Buffer_get_size(CiphertextBlob_iv(out));
  unsigned char *iv_buf = alloca(ivlen);
  buffer_t *mutable_ciphertext = CiphertextBlob_mutable_ciphertext(out);
  unsigned char *ciphertext_buf = alloca(Buffer_get_size(mutable_ciphertext));

  /* Initialise the envelope seal operation. This operation generates
   * a key for the provided cipher, and then encrypts that key. */
  if (1 != EVP_SealInit(ctx, cipher, &encrypted_key_buf, &encrypted_key_len,
                        iv_buf, &pkey, 1)) {
    PEACEMAKR_ERROR("sealinit failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  CiphertextBlob_set_iv(out, iv_buf, ivlen);
  Buffer_set_bytes(encrypted_key, encrypted_key_buf, (size_t)encrypted_key_len);

  /* Handle any AAD */
  if (aad != NULL && aad_len > 0) {
    if (aad_len > INT_MAX) {
      for (int i = 0; i < aad_len; i += (INT_MAX >> 1)) {
        if (1 != EVP_SealUpdate(ctx, NULL, &len, aad + i, (INT_MAX >> 1))) {
          PEACEMAKR_ERROR("sealupdate failed on aad, chunk %d of %d\n", i,
                          aad_len / (INT_MAX >> 1));
          EVP_CIPHER_CTX_free(ctx);
          return false;
        }
      }
    } else {
      if (1 != EVP_SealUpdate(ctx, NULL, &len, aad, (int)aad_len)) {
        PEACEMAKR_ERROR("sealupdate failed on aad\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
    }

    // Set the AAD in the CiphertextBlob
    Buffer_set_bytes(CiphertextBlob_mutable_aad(out), aad, aad_len);
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_SealUpdate can be called multiple times if necessary
   */
  if (plaintext_len > INT_MAX) {
    for (int i = 0; i < plaintext_len; i += (INT_MAX >> 1)) {
      if (1 != EVP_SealUpdate(ctx, ciphertext_buf, &len, plaintext + i,
                              (INT_MAX >> 1))) {
        PEACEMAKR_ERROR("sealupdate failed, on batch %d of %d\n", i,
                        plaintext_len / (INT_MAX >> 1));
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      ciphertext_len += len;
    }
  } else {
    if (1 != EVP_SealUpdate(ctx, ciphertext_buf, &len, plaintext,
                            (int)plaintext_len)) {
      PEACEMAKR_ERROR("sealupdate failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    ciphertext_len += len;
  }

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_SealFinal(ctx, ciphertext_buf + len, &len)) {
    PEACEMAKR_ERROR("sealfinal failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len += len;
  Buffer_set_bytes(mutable_ciphertext, ciphertext_buf, ciphertext_len);

  /* Get the tag at this point, if the algorithm provides one */
  if (tag != NULL) {
    size_t taglen = Buffer_get_size(tag);
    if (taglen > 0) {
      unsigned char tag_buf[taglen];

      if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen,
                                   tag_buf)) {
        PEACEMAKR_ERROR("getting the tag failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      Buffer_set_bytes(tag, tag_buf, taglen); // store the tag in the buffer
    }
  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return true;
}

static bool asymmetric_decrypt(const peacemakr_key_t *peacemakrkey,
                               const ciphertext_blob_t *in,
                               buffer_t **plaintext, buffer_t **aad) {
  EVP_CIPHER_CTX *ctx;

  int len = 0;
  size_t plaintext_len = 0;

  EVP_PKEY *priv_key = PeacemakrKey_asymmetric(peacemakrkey);

  const EVP_CIPHER *cipher = parse_cipher(CiphertextBlob_symm_cipher(in));

  const buffer_t *encrypted_key = CiphertextBlob_encrypted_key(in);
  const size_t encrypted_key_len = Buffer_get_size(encrypted_key);

  const buffer_t *ciphertext = CiphertextBlob_ciphertext(in);
  const unsigned char *ciphertext_buf = Buffer_get_bytes(ciphertext, NULL);
  const size_t ciphertext_len = Buffer_get_size(ciphertext);

  const buffer_t *iv = CiphertextBlob_iv(in);

  const buffer_t *stored_aad = CiphertextBlob_aad(in);
  const unsigned char *aad_buf = Buffer_get_bytes(stored_aad, NULL);
  const size_t aad_len = Buffer_get_size(stored_aad);

  const buffer_t *stored_tag = CiphertextBlob_tag(in);

  unsigned char *tag_buf = NULL;
  size_t taglen = 0;
  if (stored_tag != NULL) {
    tag_buf = (unsigned char *)Buffer_get_bytes(stored_tag, NULL);
    taglen = Buffer_get_size(stored_tag);
  }

  unsigned char *plaintext_buf = alloca(ciphertext_len << 1);

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    PEACEMAKR_ERROR("cipher_ctx_new failed\n");
    return false;
  }

  /* Initialise the decryption operation. The asymmetric private key is
   * provided and priv_key, whilst the encrypted session key is held in
   * encrypted_key */
  if (iv != NULL) {
    if (1 != EVP_OpenInit(ctx, cipher, Buffer_get_bytes(encrypted_key, NULL),
                          (int)encrypted_key_len, Buffer_get_bytes(iv, NULL),
                          priv_key)) {
      PEACEMAKR_ERROR("openinit failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  } else {
    if (1 != EVP_OpenInit(ctx, cipher, Buffer_get_bytes(encrypted_key, NULL),
                          (int)encrypted_key_len, NULL, priv_key)) {
      PEACEMAKR_ERROR("openinit failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Handle any AAD */
  if (aad != NULL && aad_len > 0) {
    if (aad_len > INT_MAX) {
      for (int i = 0; i < aad_len; i += (INT_MAX >> 1)) {
        if (1 != EVP_OpenUpdate(ctx, NULL, &len, aad_buf + i, (INT_MAX >> 1))) {
          PEACEMAKR_ERROR("openupdate failed on aad, chunk %d of %d\n", i,
                          aad_len / (INT_MAX >> 1));
          EVP_CIPHER_CTX_free(ctx);
          return false;
        }
      }
    } else {
      if (1 != EVP_OpenUpdate(ctx, NULL, &len, aad_buf, (int)aad_len)) {
        PEACEMAKR_ERROR("openupdate failed on aad\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
    }
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_OpenUpdate can be called multiple times if necessary
   */
  if (ciphertext_len > INT_MAX) {
    for (int i = 0; i < ciphertext_len; i += (INT_MAX >> 1)) {
      if (1 != EVP_OpenUpdate(ctx, plaintext_buf, &len, ciphertext_buf + i,
                              (INT_MAX >> 1))) {
        PEACEMAKR_ERROR("openupdate failed, on batch %d of %d\n", i,
                        ciphertext_len / (INT_MAX >> 1));
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      plaintext_len += len;
    }
  } else {
    if (1 != EVP_OpenUpdate(ctx, plaintext_buf, &len, ciphertext_buf,
                            (int)ciphertext_len)) {
      PEACEMAKR_ERROR("openupdate failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    plaintext_len = (size_t)len;
  }

  /* Get the tag at this point, if the algorithm provides one */
  if (taglen > 0 && tag_buf != NULL) {
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                                 (void *)tag_buf)) {
      PEACEMAKR_ERROR("getting the tag failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_OpenFinal(ctx, plaintext_buf + len, &len)) {
    PEACEMAKR_ERROR("openfinal failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  *plaintext = Buffer_new(plaintext_len);
  Buffer_set_bytes(*plaintext, plaintext_buf, plaintext_len);
  *aad = Buffer_new(aad_len);
  Buffer_set_bytes(*aad, aad_buf, aad_len);

  return true;
}

ciphertext_blob_t *peacemakr_encrypt(crypto_config_t cfg, const peacemakr_key_t *key,
                           const plaintext_t *plain, random_device_t *rand) {

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  const int cipher_block_size = EVP_CIPHER_block_size(cipher);
  size_t iv_len = (size_t)EVP_CIPHER_iv_length(cipher);
  size_t tag_len = get_taglen(cfg.symm_cipher);
  size_t aad_len = plain->aad_len;

  size_t ciphertext_len = plain->data_len + cipher_block_size - 1;
  if (plain->data_len > INT_MAX) {
    ciphertext_len =
        ((INT_MAX >> 1) + EVP_CIPHER_block_size(cipher) - 1) // max block size
        * ((plain->data_len / (INT_MAX >> 1)) +
           1); // number of blocks (rounded up)
  }

  size_t digest_len = get_digest_len(cfg.digest_algorithm);

  ciphertext_blob_t *out = CiphertextBlob_new(cfg, iv_len, tag_len, aad_len,
                                              ciphertext_len, digest_len);

  bool success = false;
  switch (cfg.mode) {
  case SYMMETRIC: {
    if (iv_len != 0) {
      CiphertextBlob_init_iv(out, rand);
    }

    success = symmetric_encrypt(key, out, plain->data, plain->data_len,
                                plain->aad, plain->aad_len);
    break;
  }
  case ASYMMETRIC: {
    success = asymmetric_encrypt(key, out, plain->data, plain->data_len,
                                 plain->aad, plain->aad_len);
    break;
  }
  }

  if (!success) {
    PEACEMAKR_ERROR("encryption failed\n");
    return NULL;
  }

  return out;
}

bool peacemakr_decrypt(const peacemakr_key_t *key, const ciphertext_blob_t *cipher,
             plaintext_t *plain) {
  bool success = false;
  buffer_t *plaintext = NULL, *aad = NULL;
  switch (CiphertextBlob_encryption_mode(cipher)) {
  case SYMMETRIC: {
    success = symmetric_decrypt(key, cipher, &plaintext, &aad);
    break;
  }
  case ASYMMETRIC: {
    success = asymmetric_decrypt(key, cipher, &plaintext, &aad);
    break;
  }
  }

  if (success) {
    const unsigned char *tmp_aad = Buffer_get_bytes(aad, &plain->aad_len);
    plain->aad = calloc(plain->aad_len, sizeof(unsigned char));
    memcpy((void *)plain->aad, tmp_aad, plain->aad_len);
    Buffer_free(aad);

    const unsigned char *tmp_plain =
        Buffer_get_bytes(plaintext, &plain->data_len);
    plain->data = calloc(plain->data_len, sizeof(unsigned char));
    memcpy((void *)plain->data, tmp_plain, plain->data_len);
    Buffer_free(plaintext);
  }

  return success;
}
