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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

static void asymmetric_sign(const peacemakr_key_t *sender_key,
                            const uint8_t *plaintext,
                            const size_t plaintext_len, const uint8_t *aad,
                            const size_t aad_len, ciphertext_blob_t *cipher) {

  EVP_MD_CTX *md_ctx;
  EVP_PKEY *sign_key = PeacemakrKey_asymmetric(sender_key);
  EXPECT_NOT_NULL_RET_NONE(
      sign_key, "can't sign the message with a NULL asymmetric key\n");

  const EVP_MD *digest_algo = parse_digest(CiphertextBlob_digest_algo(cipher));

  md_ctx = EVP_MD_CTX_new();
  EXPECT_NOT_NULL_RET_NONE(md_ctx, "md_ctx_new failed\n");

  if (1 != EVP_DigestSignInit(md_ctx, NULL, digest_algo, NULL, sign_key)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_LOG("DigestSignInit failed\n");
    EVP_MD_CTX_free(md_ctx);
    return;
  }

  EVP_MD_CTX_set_flags(md_ctx, EVP_MD_CTX_FLAG_PAD_PKCS1);

  if (aad != NULL && aad_len > 0) {
    if (1 != EVP_DigestSignUpdate(md_ctx, aad, aad_len)) {
      PEACEMAKR_OPENSSL_LOG;
      PEACEMAKR_LOG("DigestSignUpdate failed\n");
      EVP_MD_CTX_free(md_ctx);
      return;
    }
  }

  if (plaintext != NULL && plaintext_len > 0) {
    if (1 != EVP_DigestSignUpdate(md_ctx, plaintext, plaintext_len)) {
      PEACEMAKR_OPENSSL_LOG;
      PEACEMAKR_LOG("DigestSignUpdate failed\n");
      EVP_MD_CTX_free(md_ctx);
      return;
    }
  }

  // Set the digest in the message digest buffer (get the size first)
  size_t signature_len = 0;
  if (1 != EVP_DigestSignFinal(md_ctx, NULL, &signature_len)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_LOG("DigestSignFinal failed\n");
    EVP_MD_CTX_free(md_ctx);
    return;
  }
  // Realloc if necessary and sign
  buffer_t *digest_buf = CiphertextBlob_mutable_signature(cipher);
  Buffer_set_size(digest_buf, signature_len);
  unsigned char *digest_bytes = Buffer_mutable_bytes(digest_buf);
  if (1 != EVP_DigestSignFinal(md_ctx, digest_bytes, &signature_len)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_LOG("DigestSignFinal failed\n");
    EVP_MD_CTX_free(md_ctx);
    return;
  }
  Buffer_set_size(digest_buf, signature_len);

  EVP_MD_CTX_free(md_ctx);
}

void symmetric_sign(const peacemakr_key_t *key, const uint8_t *plaintext,
                    const size_t plaintext_len, const uint8_t *aad,
                    const size_t aad_len, ciphertext_blob_t *cipher) {

  uint8_t *concat_buf = calloc(plaintext_len + aad_len, sizeof(uint8_t));

  if (plaintext != NULL && plaintext_len > 0) {
    memcpy(concat_buf, plaintext, plaintext_len);
  }
  if (aad != NULL && aad_len > 0) {
    memcpy(concat_buf + plaintext_len, aad, aad_len);
  }

  size_t out_size = 0;
  uint8_t *hmac =
      peacemakr_hmac(PeacemakrKey_get_config(key).digest_algorithm, key,
                     concat_buf, plaintext_len + aad_len, &out_size);

  buffer_t *digest_buf = CiphertextBlob_mutable_signature(cipher);
  Buffer_set_size(digest_buf, out_size);
  Buffer_set_bytes(digest_buf, hmac, out_size);

  free(concat_buf);
  free(hmac);
}

void peacemakr_sign(const peacemakr_key_t *sender_key, const plaintext_t *plain,
                    ciphertext_blob_t *cipher) {

  EXPECT_NOT_NULL_RET_NONE(sender_key, false,
                           "Cannot verify with a NULL key\n");
  EXPECT_NOT_NULL_RET_NONE(cipher, false,
                           "Cannot verify with nothing to compare against\n");
  EXPECT_NOT_NULL_RET_NONE(plain, false, "Cannot verify an empty plaintext\n");

  switch (PeacemakrKey_get_config(sender_key).mode) {
  case SYMMETRIC:
    return symmetric_sign(sender_key, plain->data, plain->data_len, plain->aad,
                          plain->aad_len, cipher);
  case ASYMMETRIC:
    return asymmetric_sign(sender_key, plain->data, plain->data_len, plain->aad,
                           plain->aad_len, cipher);
  }
}

static bool asymmetric_verify(const peacemakr_key_t *sender_key,
                              const uint8_t *plaintext,
                              const size_t plaintext_len, const uint8_t *aad,
                              const size_t aad_len,
                              const ciphertext_blob_t *cipher) {
  EVP_MD_CTX *md_ctx;
  EVP_PKEY *verif_key = PeacemakrKey_asymmetric(sender_key);
  EXPECT_NOT_NULL_RET_VALUE(
      verif_key, false,
      "can't verify the message with a NULL asymmetric key\n");

  const EVP_MD *digest_algo = parse_digest(CiphertextBlob_digest_algo(cipher));

  md_ctx = EVP_MD_CTX_new();
  EXPECT_NOT_NULL_RET_VALUE(md_ctx, false, "md_ctx_new failed\n");

  const buffer_t *stored_digest = CiphertextBlob_signature(cipher);
  size_t digestlen = 0;
  unsigned char *digest_buf = NULL;
  if (stored_digest != NULL) {
    digest_buf = (unsigned char *)Buffer_get_bytes(stored_digest, &digestlen);
  }

  if (1 != EVP_DigestVerifyInit(md_ctx, NULL, digest_algo, NULL, verif_key)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_LOG("DigestVerifyInit failed\n");
    EVP_MD_CTX_free(md_ctx);
    return false;
  }

  EVP_MD_CTX_set_flags(md_ctx, EVP_MD_CTX_FLAG_PAD_PKCS1);

  if (aad != NULL && aad_len > 0) {
    if (1 != EVP_DigestVerifyUpdate(md_ctx, aad, aad_len)) {
      PEACEMAKR_OPENSSL_LOG;
      PEACEMAKR_LOG("DigestVerifyInit failed\n");
      EVP_MD_CTX_free(md_ctx);
      return false;
    }
  }

  if (plaintext != NULL && plaintext_len > 0) {
    if (1 != EVP_DigestVerifyUpdate(md_ctx, plaintext, plaintext_len)) {
      PEACEMAKR_OPENSSL_LOG;
      PEACEMAKR_LOG("DigestVerifyInit failed\n");
      EVP_MD_CTX_free(md_ctx);
      return false;
    }
  }

  if (1 != EVP_DigestVerifyFinal(md_ctx, digest_buf, digestlen)) {
    PEACEMAKR_OPENSSL_LOG;
    PEACEMAKR_LOG("DigestVerifyFinal failed\n");
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(md_ctx);
    return false;
  }

  EVP_MD_CTX_free(md_ctx);

  return true;
}

static bool symmetric_verify(const peacemakr_key_t *key,
                             const uint8_t *plaintext,
                             const size_t plaintext_len, const uint8_t *aad,
                             const size_t aad_len,
                             const ciphertext_blob_t *cipher) {

  uint8_t *concat_buf = calloc(plaintext_len + aad_len, sizeof(uint8_t));
  if (plaintext != NULL && plaintext_len > 0) {
    memcpy(concat_buf, plaintext, plaintext_len);
  }
  if (aad != NULL && aad_len > 0) {
    memcpy(concat_buf + plaintext_len, aad, aad_len);
  }

  size_t out_size = 0;
  uint8_t *hmac =
      peacemakr_hmac(PeacemakrKey_get_config(key).digest_algorithm, key,
                     concat_buf, plaintext_len + aad_len, &out_size);

  const buffer_t *digest_buf = CiphertextBlob_signature(cipher);
  size_t stored_size = 0;
  const uint8_t *stored_hmac = Buffer_get_bytes(digest_buf, &stored_size);

  if (stored_size != out_size) {
    free(concat_buf);
    free(hmac);
    return false;
  }

  if (0 != CRYPTO_memcmp(hmac, stored_hmac, out_size)) {
    // failed
    free(concat_buf);
    free(hmac);
    return false;
  }

  free(concat_buf);
  free(hmac);
  return true;
}

bool peacemakr_verify(const peacemakr_key_t *sender_key,
                      const plaintext_t *plain, ciphertext_blob_t *cipher) {

  EXPECT_NOT_NULL_RET_VALUE(sender_key, false,
                            "Cannot verify with a NULL key\n");
  EXPECT_NOT_NULL_RET_VALUE(cipher, false,
                            "Cannot verify with nothing to compare against\n");
  EXPECT_NOT_NULL_RET_VALUE(plain, false, "Cannot verify an empty plaintext\n");

  bool success = false;

  if (Buffer_get_size(CiphertextBlob_signature(cipher)) == 1) {
    PEACEMAKR_LOG("No signature to verify\n");
    CiphertextBlob_free(cipher);
    cipher = NULL;
    return true;
  }

  switch (PeacemakrKey_get_config(sender_key).mode) {
  case SYMMETRIC:
    success = symmetric_verify(sender_key, plain->data, plain->data_len,
                               plain->aad, plain->aad_len, cipher);
    break;
  case ASYMMETRIC:
    success = asymmetric_verify(sender_key, plain->data, plain->data_len,
                                plain->aad, plain->aad_len, cipher);
    break;
  }

  CiphertextBlob_free(cipher);
  cipher = NULL;

  return success;
}
