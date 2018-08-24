//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CRYPTO_H
#define PEACEMAKR_CORE_CRYPTO_CRYPTO_H

#include "random.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PEACEMAKR_CORE_CRYPTO_VERSION (uint8_t)1

typedef enum {
  AES_128_GCM,
  AES_192_GCM,
  AES_256_GCM,
  CHACHA20_POLY1305
} symmetric_cipher;

typedef enum {
  NONE,
  RSA_2048,
  RSA_4096,
  //  EC25519, // SealInit fails when using EC25519 - reason unknown
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

peacemakr_key_t *PeacemakrKey_new(crypto_config_t cfg, random_device_t *rand);
peacemakr_key_t *PeacemakrKey_new_bytes(crypto_config_t cfg,
                                        const uint8_t *buf);
void PeacemakrKey_free(peacemakr_key_t *key);

ciphertext_blob_t *peacemakr_encrypt(crypto_config_t cfg,
                                     const peacemakr_key_t *key,
                                     const plaintext_t *plain,
                                     random_device_t *rand);

bool peacemakr_decrypt(const peacemakr_key_t *key,
                       const ciphertext_blob_t *cipher, plaintext_t *plain);

// base64 encoded
const uint8_t *serialize_blob(ciphertext_blob_t *cipher, size_t *out_size);
const ciphertext_blob_t *deserialize_blob(const uint8_t *b64_serialized_cipher,
                                          size_t serialized_len);

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTO_H
