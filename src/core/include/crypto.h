//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CRYPTO_H
#define PEACEMAKR_CORE_CRYPTO_CRYPTO_H

#include <random.h>
#include <stddef.h>
#include <stdint.h>

#define PEACEMAKR_CORE_CRYPTO_VERSION (uint32_t)0x010

typedef enum {
  AES_128_GCM,
  AES_192_GCM,
  AES_256_GCM,
  AES_128_CBC,
  AES_192_CBC,
  AES_256_CBC,
  AES_128_CFB,
  AES_192_CFB,
  AES_256_CFB,
  AES_128_ECB,
  AES_192_ECB,
  AES_256_ECB,
  AES_128_OFB,
  AES_192_OFB,
  AES_256_OFB,
  AES_128_CTR,
  AES_192_CTR,
  AES_256_CTR,
  AES_128_CCM,
  AES_192_CCM,
  AES_256_CCM,
  AES_128_WRAP,
  AES_192_WRAP,
  AES_256_WRAP,
  AES_128_WRAP_PAD,
  AES_192_WRAP_PAD,
  AES_256_WRAP_PAD,
  AES_128_XTS,
  AES_256_XTS,
  AES_128_CBC_HMAC_SHA1,
  AES_256_CBC_HMAC_SHA1,
  AES_128_CBC_HMAC_SHA256,
  AES_256_CBC_HMAC_SHA256,
  CHACHA20,
  CHACHA20_POLY1305
} symmetric_cipher;

typedef enum {
  NONE,
  EC25519,
  RSA_2048,
  RSA_4096,
} asymmetric_cipher;

typedef enum { SHA_224, SHA_256, SHA_384, SHA_512 } message_digest_algorithm;

typedef enum { SYMMETRIC, ASYMMETRIC } encryption_mode;

typedef struct {
  encryption_mode mode;

  // OpenSSL uses the asymmetric cipher to encrypt a symmetric key, so we need
  // asymmetric and symmetric ciphers
  symmetric_cipher symm_cipher;
  asymmetric_cipher asymm_cipher;

  message_digest_algorithm digest_algorithm;
} crypto_config_t;

typedef struct {
  const unsigned char *data;
  size_t data_len;
  const unsigned char *aad;
  size_t aad_len;
} plaintext_t;

typedef struct CiphertextBlob
    ciphertext_blob_t; // this will have inside it the
                       // tag/IV/whatever is needed to decrypt

typedef struct PeacemakrKey
    peacemakr_key_t; // this will have inside it the EVP_PKEY or
                     // alternatively just the symmetric key

peacemakr_key_t *PeacemakrKey_new(crypto_config_t cfg, random_device_t rand);
void PeacemakrKey_free(peacemakr_key_t *key);

ciphertext_blob_t *encrypt(crypto_config_t cfg, const peacemakr_key_t **key, int num_keys,
                           const plaintext_t *plain);
int decrypt(const peacemakr_key_t *key, const ciphertext_blob_t *cipher,
            plaintext_t *plain);

// base64 encoded
const uint8_t *serialize_blob(const ciphertext_blob_t *cipher);
const ciphertext_blob_t *deserialize_blob(const uint8_t *serialized_cipher);

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTO_H
