//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "crypto.h"

#include "CiphertextBlob.h"
#include "EVPHelper.h"
#include "Key.h"
#include "Logging.h"

#include <memory.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdbool.h>

// None of the input lengths can be larger than INT_MAX
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

  EXPECT_NOT_NULL_RET_VALUE(
      key, false, "can't do symmetric crypto with a NULL symmetric key\n");
  EXPECT_NOT_NULL_RET_VALUE(
      Buffer_get_bytes(key, NULL), false,
      "can't do symmetric crypto with a NULL symmetric key\n");

  const buffer_t *iv = CiphertextBlob_iv(out);
  buffer_t *tag = CiphertextBlob_mutable_tag(out);
  buffer_t *aad_buf = CiphertextBlob_mutable_aad(out);
  buffer_t *ciphertext_buf = CiphertextBlob_mutable_ciphertext(out);

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  EXPECT_NOT_NULL_RET_VALUE(ctx, false, "cipher_ctx_new failed\n");

  /* Initialize the encryption */
  if (iv != NULL) {
    OPENSSL_CHECK_RET_VALUE(EVP_EncryptInit_ex(ctx, cipher, NULL,
                                               Buffer_get_bytes(key, NULL),
                                               Buffer_get_bytes(iv, NULL)),
                            ctx, false)
  } else {
    OPENSSL_CHECK_RET_VALUE(EVP_EncryptInit_ex(ctx, cipher, NULL,
                                               Buffer_get_bytes(key, NULL),
                                               NULL),
                            ctx, false)
  }

  /* Handle any AAD */
  if (aad != NULL && aad_len > 0) {
    OPENSSL_CHECK_RET_VALUE(
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len), ctx, false);

    // Set the AAD in the CiphertextBlob
    Buffer_set_bytes(aad_buf, aad, aad_len);
  }

  /* Now set up to do the actual encryption */
  unsigned char *ciphertext = Buffer_mutable_bytes(ciphertext_buf);

  if (plaintext == NULL || plaintext_len == 0) {
    PEACEMAKR_LOG("cannot encrypt an empty string\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  OPENSSL_CHECK_RET_VALUE(
      EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len),
      ctx, false);
  ciphertext_len = (size_t)len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  OPENSSL_CHECK_RET_VALUE(
      EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len), ctx, false);
  ciphertext_len += len;
  Buffer_set_size(ciphertext_buf, ciphertext_len);

  /* Get the tag at this point, if the algorithm provides one */
  if (tag != NULL) {
    size_t taglen = Buffer_get_size(tag);
    if (taglen > 0) {
      unsigned char *tag_buf = Buffer_mutable_bytes(tag);

      OPENSSL_CHECK_RET_VALUE(
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen, tag_buf),
          ctx, false);
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

  EXPECT_NOT_NULL_RET_VALUE(
      key, false, "can't do symmetric crypto with a NULL symmetric key\n");
  EXPECT_NOT_NULL_RET_VALUE(
      Buffer_get_bytes(key, NULL), false,
      "can't do symmetric crypto with a NULL symmetric key\n");

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
  EXPECT_NOT_NULL_RET_VALUE(ctx, false, "cipher_ctx_new failed\n");

  /* Initialize the decryption */
  if (iv != NULL) {
    OPENSSL_CHECK_RET_VALUE(EVP_DecryptInit_ex(ctx, cipher, NULL,
                                               Buffer_get_bytes(key, NULL),
                                               Buffer_get_bytes(iv, NULL)),
                            ctx, false);
  } else {
    OPENSSL_CHECK_RET_VALUE(EVP_DecryptInit_ex(ctx, cipher, NULL,
                                               Buffer_get_bytes(key, NULL),
                                               NULL),
                            ctx, false);
  }

  /* Handle any AAD */
  if (aad_buf != NULL && aad_len > 0) {
    OPENSSL_CHECK_RET_VALUE(
        EVP_DecryptUpdate(ctx, NULL, &len, aad_buf, (int)aad_len), ctx, false);
  }

  /* Now set up to do the actual decryption */
  *plaintext = Buffer_new(ciphertext_len << 1);
  unsigned char *plaintext_buf = Buffer_mutable_bytes(*plaintext);

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  OPENSSL_CHECK_RET_VALUE(EVP_DecryptUpdate(ctx, plaintext_buf, &len,
                                            ciphertext_buf,
                                            (int)ciphertext_len),
                          ctx, false);
  plaintext_len = (size_t)len;

  if (taglen > 0 && tag_buf != NULL) {
    OPENSSL_CHECK_RET_VALUE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                                (int)taglen, (void *)tag_buf),
                            ctx, false);
  }

  /* Finalise the decryption. */
  OPENSSL_CHECK_RET_VALUE(
      EVP_DecryptFinal_ex(ctx, plaintext_buf + plaintext_len, &len), ctx,
      false);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  /* Success */
  plaintext_len += len;

  Buffer_set_size(*plaintext, plaintext_len);
  if (aad_buf != NULL && aad_len > 0) {
    *aad = Buffer_new(aad_len);
    Buffer_set_bytes(*aad, aad_buf, aad_len);
  }
  return true;
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
  EXPECT_NOT_NULL_RET_VALUE(
      pkey, false, "can't do asymmetric crypto with a NULL asymmetric key\n");

  buffer_t *tag = CiphertextBlob_mutable_tag(out);

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  EXPECT_NOT_NULL_RET_VALUE(ctx, false, "cipher_ctx_new failed\n");

  buffer_t *encrypted_key = CiphertextBlob_mutable_encrypted_key(out);
  size_t keylen = Buffer_get_size(encrypted_key);
  int encrypted_key_len = 0;
  unsigned char *encrypted_key_buf = alloca(keylen);

  size_t ivlen = Buffer_get_size(CiphertextBlob_iv(out));
  unsigned char *iv_buf = alloca(ivlen);

  buffer_t *mutable_ciphertext = CiphertextBlob_mutable_ciphertext(out);
  unsigned char *ciphertext_buf = Buffer_mutable_bytes(mutable_ciphertext);

  /* Initialise the envelope seal operation. This operation generates
   * a key for the provided cipher, and then encrypts that key. */
  if (1 != EVP_SealInit(ctx, cipher, &encrypted_key_buf, &encrypted_key_len,
                        iv_buf, &pkey, 1)) {
    PEACEMAKR_LOG("SealInit failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  CiphertextBlob_set_iv(out, iv_buf, ivlen);
  Buffer_set_size(encrypted_key, (size_t)encrypted_key_len);
  Buffer_set_bytes(encrypted_key, encrypted_key_buf, (size_t)encrypted_key_len);

  /* Handle any AAD */
  if (aad != NULL && aad_len > 0) {
    if (1 != EVP_SealUpdate(ctx, NULL, &len, aad, (int)aad_len)) {
      PEACEMAKR_LOG("SealUpdate failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Set the AAD in the CiphertextBlob
    Buffer_set_bytes(CiphertextBlob_mutable_aad(out), aad, aad_len);
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_SealUpdate can be called multiple times if necessary
   */
  if (1 != EVP_SealUpdate(ctx, ciphertext_buf, &len, plaintext,
                          (int)plaintext_len)) {
    PEACEMAKR_LOG("SealUpdate failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len += len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_SealFinal(ctx, ciphertext_buf + ciphertext_len, &len)) {
    PEACEMAKR_LOG("SealFinal failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len += len;
  Buffer_set_size(mutable_ciphertext, ciphertext_len);

  /* Get the tag at this point, if the algorithm provides one */
  if (tag != NULL) {
    size_t taglen = Buffer_get_size(tag);
    if (taglen > 0) {
      unsigned char *tag_buf = Buffer_mutable_bytes(tag);

      if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen,
                                   tag_buf)) {
        PEACEMAKR_LOG("GET_TAG failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
    }
  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return true;
}

static bool asymmetric_decrypt(const peacemakr_key_t *pkey,
                               const ciphertext_blob_t *in,
                               buffer_t **plaintext, buffer_t **aad) {
  EVP_CIPHER_CTX *ctx;

  int len = 0;
  size_t plaintext_len = 0;

  EVP_PKEY *priv_key = PeacemakrKey_asymmetric(pkey);
  EXPECT_NOT_NULL_RET_VALUE(
      priv_key, false,
      "can't do asymmetric crypto with a NULL asymmetric key\n");

  const EVP_CIPHER *cipher = parse_cipher(CiphertextBlob_symm_cipher(in));

  const buffer_t *encrypted_key = CiphertextBlob_encrypted_key(in);
  const size_t encrypted_key_len = Buffer_get_size(encrypted_key);

  const buffer_t *ciphertext = CiphertextBlob_ciphertext(in);
  const unsigned char *ciphertext_buf = Buffer_get_bytes(ciphertext, NULL);
  const size_t ciphertext_len = Buffer_get_size(ciphertext);

  const buffer_t *iv = CiphertextBlob_iv(in);

  const buffer_t *stored_aad = CiphertextBlob_aad(in);
  size_t aad_len = 0;
  unsigned char *aad_buf = NULL;
  if (stored_aad != NULL) {
    aad_buf = (unsigned char *)Buffer_get_bytes(stored_aad, &aad_len);
  }

  const buffer_t *stored_tag = CiphertextBlob_tag(in);
  size_t taglen = 0;
  unsigned char *tag_buf = NULL;
  if (stored_tag != NULL) {
    tag_buf = (unsigned char *)Buffer_get_bytes(stored_tag, &taglen);
  }

  *plaintext = Buffer_new(ciphertext_len << 1);
  unsigned char *plaintext_buf = Buffer_mutable_bytes(*plaintext);

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  EXPECT_NOT_NULL_RET_VALUE(ctx, false, "cipher_ctx_new failed\n");

  /* Initialise the decryption operation. The asymmetric private key is
   * provided and priv_key, whilst the encrypted session key is held in
   * encrypted_key */
  if (iv != NULL) {
    if (1 != EVP_OpenInit(ctx, cipher, Buffer_get_bytes(encrypted_key, NULL),
                          (int)encrypted_key_len, Buffer_get_bytes(iv, NULL),
                          priv_key)) {
      PEACEMAKR_LOG("OpenInit failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

  } else {
    if (1 != EVP_OpenInit(ctx, cipher, Buffer_get_bytes(encrypted_key, NULL),
                          (int)encrypted_key_len, NULL, priv_key)) {
      PEACEMAKR_LOG("OpenInit failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Handle any AAD */
  if (aad != NULL && aad_len > 0) {
    if (1 != EVP_OpenUpdate(ctx, NULL, &len, aad_buf, (int)aad_len)) {
      PEACEMAKR_LOG("OpenUpdate failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_OpenUpdate can be called multiple times if necessary
   */
  if (1 != EVP_OpenUpdate(ctx, plaintext_buf, &len, ciphertext_buf,
                          (int)ciphertext_len)) {
    PEACEMAKR_LOG("OpenUpdate failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  plaintext_len = (size_t)len;

  /* Get the tag at this point, if the algorithm provides one */
  if (taglen > 0 && tag_buf != NULL) {
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                                 (void *)tag_buf)) {
      PEACEMAKR_LOG("SET_TAG failed\n");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_OpenFinal(ctx, plaintext_buf + plaintext_len, &len)) {
    PEACEMAKR_LOG("OpenFinal failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  Buffer_set_size(*plaintext, plaintext_len);
  if (aad_buf != NULL && aad_len > 0) {
    *aad = Buffer_new(aad_len);
    Buffer_set_bytes(*aad, aad_buf, aad_len);
  }
  return true;
}

ciphertext_blob_t *peacemakr_encrypt(const peacemakr_key_t *recipient_key,
                                     const plaintext_t *plain,
                                     random_device_t *rand) {

  PEACEMAKR_LOG("LOOK WE MADE IT INSIDE ...\n");

  EXPECT_NOT_NULL_RET(recipient_key, "recipient key was null\n");
  EXPECT_NOT_NULL_RET(plain, "plain was null\n");
  EXPECT_NOT_NULL_RET(rand, "rand was null\n");
  EXPECT_TRUE_RET(plain->data_len <= INT_MAX,
                  "Data was too big, needs to be broken up\n");
  EXPECT_TRUE_RET(plain->aad_len <= INT_MAX,
                  "AAD was too big, needs to be broken up\n");
  EXPECT_TRUE_RET((plain->data != NULL && plain->data_len > 0),
                  "No data to encrypt\n");

  PEACEMAKR_LOG("OK NOTHING IS NULL WAHTEVERZ ...\n");

  const crypto_config_t cfg = PeacemakrKey_get_config(recipient_key);


  PEACEMAKR_LOG("OK 1 ...\n");

  const EVP_CIPHER *cipher = parse_cipher(cfg.symm_cipher);
  EXPECT_NOT_NULL_RET(cipher, "parsing openssl cipher failed\n");

  PEACEMAKR_LOG("OK 2 ...\n");

  const int cipher_block_size = EVP_CIPHER_block_size(cipher);

  PEACEMAKR_LOG("OK 3 ...\n");

  // guard against the possibility of getting a weird value
  const int ossl_iv_len = EVP_CIPHER_iv_length(cipher);
  size_t iv_len = (ossl_iv_len > EVP_MAX_IV_LENGTH || ossl_iv_len <= 0)
                      ? EVP_MAX_IV_LENGTH
                      : (size_t)ossl_iv_len;

  size_t tag_len = get_taglen(cfg.symm_cipher);
  size_t aad_len = plain->aad_len;

  size_t ciphertext_len = plain->data_len + cipher_block_size - 1;

  EXPECT_TRUE_RET((ciphertext_len != 0), "data had length: %d\n",
                  plain->data_len);

  // Just initialize the buffer, it'll get resized later during sign/verify
  ciphertext_blob_t *out =
      CiphertextBlob_new(cfg, iv_len, tag_len, aad_len, ciphertext_len, 1);

  // always init the iv...worst case you seed the random state
  CiphertextBlob_init_iv(out, rand);

  PEACEMAKR_LOG("OK 100 ...\n");

  bool success = false;
  switch (cfg.mode) {
  case SYMMETRIC: {
    success = symmetric_encrypt(recipient_key, out, plain->data,
                                plain->data_len, plain->aad, plain->aad_len);
    break;
  }
  case ASYMMETRIC: {
    success = asymmetric_encrypt(recipient_key, out, plain->data,
                                 plain->data_len, plain->aad, plain->aad_len);
    break;
  }
  }

  EXPECT_TRUE_RET(success, "encryption failed\n");

  return out;
}

decrypt_code peacemakr_decrypt(const peacemakr_key_t *recipient_key,
                               ciphertext_blob_t *cipher, plaintext_t *plain) {

  EXPECT_NOT_NULL_RET_VALUE(plain, false, "plain was null\n");
  EXPECT_NOT_NULL_RET_VALUE(cipher, false, "cipher was null\n");
  EXPECT_NOT_NULL_RET_VALUE(recipient_key, false, "recipient_key was null\n");

  bool success = false;
  buffer_t *plaintext = NULL, *aad = NULL;

  // If the signature buffer has size 1 then there's no signature and we should
  // free the ciphertext.
  bool should_free_ciphertext =
      Buffer_get_size(CiphertextBlob_signature(cipher)) == 1;

  switch (CiphertextBlob_encryption_mode(cipher)) {
  case SYMMETRIC: {
    success = symmetric_decrypt(recipient_key, cipher, &plaintext, &aad);
    break;
  }
  case ASYMMETRIC: {
    success = asymmetric_decrypt(recipient_key, cipher, &plaintext, &aad);
    break;
  }
  }

  if (success) {
    if (aad != NULL) {
      const unsigned char *tmp_aad = Buffer_get_bytes(aad, &plain->aad_len);
      plain->aad = calloc(plain->aad_len, sizeof(unsigned char));
      memcpy((void *)plain->aad, tmp_aad, plain->aad_len);
      Buffer_free(aad);
    } else {
      plain->aad = NULL;
      plain->aad_len = 0;
    }
    const unsigned char *tmp_plain =
        Buffer_get_bytes(plaintext, &plain->data_len);
    plain->data = calloc(plain->data_len, sizeof(unsigned char));
    memcpy((void *)plain->data, tmp_plain, plain->data_len);
    Buffer_free(plaintext);
  } else { // fill with zeros
    plain->aad_len = (size_t)rand() % (2 << 8);
    plain->aad = calloc(plain->aad_len, sizeof(unsigned char));
    plain->data_len = (size_t)rand() % (2 << 8);
    plain->data = calloc(plain->data_len, sizeof(unsigned char));
  }

  if (should_free_ciphertext) {
    CiphertextBlob_free(cipher);
    cipher = NULL;
    return DECRYPT_SUCCESS;
  }

  if (success) {
    return DECRYPT_NEED_VERIFY;
  }

  return DECRYPT_FAILED;
}

bool peacemakr_get_unverified_aad(ciphertext_blob_t *cipher,
                                  plaintext_t *plain) {
  EXPECT_NOT_NULL_RET_VALUE(plain, false, "plain was null\n");
  EXPECT_NOT_NULL_RET_VALUE(cipher, false, "cipher was null\n");

  const buffer_t *aad_buf = CiphertextBlob_aad(cipher);

  EXPECT_NOT_NULL_RET_VALUE(aad_buf, true, "No AAD in ciphertext\n");

  const unsigned char *tmp_aad = Buffer_get_bytes(aad_buf, &plain->aad_len);
  plain->aad = calloc(plain->aad_len, sizeof(unsigned char));
  memcpy((void *)plain->aad, tmp_aad, plain->aad_len);

  // Initialize the data to NULL
  plain->data = NULL;
  plain->data_len = 0;
  return true;
}
