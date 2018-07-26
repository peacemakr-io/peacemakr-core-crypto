//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <stdint.h>

#include <openssl/evp.h>

#include <CryptoMemory.h>
#include <memory.h>

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(EncryptedBlob_, name)

static uint16_t taglen = 16;

// version first, tag last
struct EncryptedBlob {
  uint8_t m_version_[3]; // major, minor, patch
  char *m_cipher_name_;  // the name of the cipher used - openssl tracks valid combinations on its own
  secure_buffer_t *m_iv_;
  secure_buffer_t *m_aad_;
  secure_buffer_t *m_tag_;
  secure_buffer_t *m_ciphertext_;
};

typedef struct EncryptedBlob encrypted_blob_t;

encrypted_blob_t *API(new)(crypto_context_t *ctx, random_device_t *rng,
                           secure_buffer_t *plaintext, secure_buffer_t *aad,
                           secure_buffer_t *key) {

  if (ctx != SecureBuffer_get_ctx(plaintext) || ctx != SecureBuffer_get_ctx(aad) || ctx != SecureBuffer_get_ctx(key)) {
    printf("non-matching contexts, aborting operation");
    return NULL;
  }

  EVP_CIPHER_CTX *cipher_ctx;
  if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
    printf("openssl init failed");
    return NULL;
  }

  const char *cipher_name = CryptoContext_get_cipher_mode(ctx);
  const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);

  if (1 != EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, NULL, NULL)) {
    printf("openssl encryptinit failed");
    return NULL;
  }

  int iv_len = EVP_CIPHER_iv_length(cipher);
  if (iv_len <= 0) {
    printf("get iv len failed");
    return NULL;
  }

  secure_buffer_t *iv = SecureBuffer_new(ctx, (size_t)iv_len);
  SecureBuffer_init_rand(iv, rng); // get a new IV every time

  if (1 != EVP_EncryptInit_ex(cipher_ctx, NULL, NULL,
                              SecureBuffer_get_bytes(key, NULL),
                              SecureBuffer_get_bytes(iv, NULL))) {
    printf("encrypt init - key init failed");
    return NULL;
  }

  int len = 0;
  size_t aad_out_size = 0;
  const unsigned char *aad_bytes = SecureBuffer_get_bytes(aad, &aad_out_size);

  if (1 !=
      EVP_EncryptUpdate(cipher_ctx, NULL, &len, aad_bytes, (int)aad_out_size)) {
    printf("encrypt update failed");
    return NULL;
  }

  // TODO: make this a better estimate
  size_t ciphertext_size = SecureBuffer_get_size(plaintext) * 2;
  secure_buffer_t *ciphertext = SecureBuffer_new(ctx, ciphertext_size);

  size_t plaintext_out_size = 0;
  const unsigned char *plaintext_bytes =
      SecureBuffer_get_bytes(plaintext, &plaintext_out_size);

  unsigned char *ciphertext_bytes = SecureBuffer_get_bytes(ciphertext, NULL);

  if (1 != EVP_EncryptUpdate(cipher_ctx, ciphertext_bytes, &len,
                             plaintext_bytes, (int)plaintext_out_size)) {
    printf("encrypt update with plaintext failed");
    return NULL;
  }
  SecureBuffer_set_size(ciphertext, (size_t)len);

  if (1 != EVP_EncryptFinal_ex(cipher_ctx, ciphertext_bytes + len, &len)) {
    printf("encrypt finalize failed");
    return NULL;
  }
  SecureBuffer_set_size(ciphertext,
                        SecureBuffer_get_size(ciphertext) + (size_t)len);

  secure_buffer_t *tag = SecureBuffer_new(ctx, taglen); // openssl tag length

  if (1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_AEAD_GET_TAG, taglen,
                               SecureBuffer_get_bytes(tag, NULL))) {
    printf("get tag failed");
    return NULL;
  }

  EVP_CIPHER_CTX_free(cipher_ctx);

  encrypted_blob_t *ret_blob = malloc(sizeof(encrypted_blob_t));
  ret_blob->m_version_[0] = 0;
  ret_blob->m_version_[1] = 1;
  ret_blob->m_version_[2] = 0;

  ret_blob->m_cipher_name_ = malloc(strlen(cipher_name) + 1);
  strncpy(ret_blob->m_cipher_name_, cipher_name, strlen(cipher_name) + 1);

  ret_blob->m_iv_ = iv;
  ret_blob->m_aad_ = aad;
  ret_blob->m_tag_ = tag;
  ret_blob->m_ciphertext_ = ciphertext;

  return ret_blob;
}

secure_buffer_t *API(read)(crypto_context_t *ctx, encrypted_blob_t *blob) {

  EVP_CIPHER_CTX *cipher_ctx;
  if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
    printf("openssl init failed");
    return NULL;
  }

  const char *cipher_name = blob->m_cipher_name_;
  const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);

  if (1 != EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, NULL, NULL)) {
    printf("openssl decryptinit failed");
    return NULL;
  }

  int len = 0;

  if (1 != EVP_DecryptUpdate(cipher_ctx, NULL, &len,
                             SecureBuffer_get_bytes(blob->m_aad_, NULL),
                             (int)SecureBuffer_get_size(blob->m_aad_))) {
    printf("decrypt update failed");
    return NULL;
  }

  size_t ciphertext_size = SecureBuffer_get_size(blob->m_ciphertext_);
  secure_buffer_t *plaintext = SecureBuffer_new(ctx, ciphertext_size);
  unsigned char *plaintext_bytes = SecureBuffer_get_bytes(plaintext, NULL);

  const unsigned char *ciphertext_bytes =
      SecureBuffer_get_bytes(blob->m_ciphertext_, NULL);

  if (1 != EVP_DecryptUpdate(cipher_ctx, plaintext_bytes, &len,
                             ciphertext_bytes, (int)ciphertext_size)) {
    printf("decrypt update with ciphertext failed");
    return NULL;
  }
  SecureBuffer_set_size(plaintext, (size_t)len);

  if (1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_AEAD_SET_TAG, taglen,
                               SecureBuffer_get_bytes(blob->m_tag_, NULL))) {
    printf("set tag failed");
    return NULL;
  }

  int ret = EVP_DecryptFinal_ex(cipher_ctx, plaintext_bytes + len, &len);

  EVP_CIPHER_CTX_free(cipher_ctx);

  if (ret > 0) {
    SecureBuffer_set_size(plaintext,
                          SecureBuffer_get_size(plaintext) + (size_t)len);
    return plaintext;
  } else {
    printf("decrypt failed");
    return NULL;
  }
}

void API(free)(encrypted_blob_t *blob) {
  free(blob->m_cipher_name_);
  SecureBuffer_free(blob->m_iv_);
  SecureBuffer_free(blob->m_aad_);
  SecureBuffer_free(blob->m_tag_);
  SecureBuffer_free(blob->m_ciphertext_);
  free(blob);
}
