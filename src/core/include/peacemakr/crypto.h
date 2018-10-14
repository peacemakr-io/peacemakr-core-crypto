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

#include <openssl/ossl_typ.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PEACEMAKR_CORE_CRYPTO_VERSION (uint8_t)1
#define PEACEMAKR_CORE_CRYPTO_VERSION_MAX (uint8_t)1

/**
 * @file peacemakr/crypto.h
 * Peacemakr core crypto
 */

/**
 * @brief Peacemakr supported symmetric cipher algorithms
 *
 * We currently support these algorithms because they follow the same EVP_*
 * interface in OpenSSL and can be reliably swapped in and out for each other.
 */
typedef enum {
  AES_128_GCM,
  AES_192_GCM,
  AES_256_GCM,
  CHACHA20_POLY1305
} symmetric_cipher;

/**
 * @brief Peacemakr supported asymmetric cipher algorithms
 *
 * EC25519 causes failure during EVP_SealInit call for reasons unknown
 * so only the RSA_* algorithms are currently supported
 */
typedef enum {
  NONE,
  RSA_2048,
  RSA_4096,
  //  EC25519,
} asymmetric_cipher;

/**
 * @brief Peacemakr supported message digest algorithms
 *
 * We actually technically support most any of the OpenSSL digest algorithms.
 * However, many of them are insecure or have collisions, so we have selected
 * the ones that are considered to be secure.
 */
typedef enum { SHA_224, SHA_256, SHA_384, SHA_512 } message_digest_algorithm;

/**
 * @brief Peacemakr supported encryption modes
 */
typedef enum { SYMMETRIC, ASYMMETRIC } encryption_mode;

/**
 * @brief Configures the crypto library calls
 *
 * Uses the above enums to configure the library calls so that the encryption is
 * performed as required
 */
typedef struct {
  encryption_mode mode;

  //! OpenSSL uses the asymmetric cipher to encrypt a symmetric key so both are
  //! needed in the asymmetric case
  symmetric_cipher symm_cipher;

  asymmetric_cipher asymm_cipher;

  message_digest_algorithm digest_algorithm;
} crypto_config_t;

/**
 * @brief Convenience datastructure for holding plaintext and AAD
 *
 * Holds simple strings that are the plaintext data and AAD to be encrypted. The
 * library also decrypts into this struct for uniformity.
 */
typedef struct {
  const unsigned char *data;
  size_t data_len;
  const unsigned char *aad;
  size_t aad_len;
} plaintext_t;

//! Opaque type holding everything necessary to decrypt the encrypted message,
//! save for the key iteself
typedef struct CiphertextBlob ciphertext_blob_t;

//! Opaque type holding the key itself (EVP_PKEY or just a symmetric key)
typedef struct PeacemakrKey peacemakr_key_t;

/**
 * Get max supported version by this library. Compile time constant.
 */
static inline uint8_t get_max_version() {
  return PEACEMAKR_CORE_CRYPTO_VERSION_MAX;
}

/**
 * Should be called once on startup. Ensures that the system's random number
 * generator is well seeded and any numbers generated have sufficient entropy.
 */
bool peacemakr_init();

/**
 * Create a new peacemakr_key_t from scratch with user-defined \p cfg and \p
 * rand to configure the key creation. It is recommended that \p rand come from
 * /dev/urandom or similar. \returns A newly created peacemakr key for use in
 * other library calls.
 */
peacemakr_key_t *PeacemakrKey_new(crypto_config_t cfg, random_device_t *rand);

/**
 * Create a new peacemakr_key_t from bytes generated externally. This
 * function applies only to symmetric encryption provided by this library.
 * Uses \p cfg to configure the key being created. Stores \p buf for use as
 * a symmetric key - it is recommended that these come from /dev/urandom or
 * similar. \returns A newly created peacemakr key for use in other library
 * calls.
 */
peacemakr_key_t *PeacemakrKey_new_bytes(crypto_config_t cfg, const uint8_t *buf,
                                        const size_t bufsize);

/**
 * Create a new peacemakr_key_t from a pem file generated externally. This
 * function applies only to asymmetric encryption provided by this library,
 * and the pem file must be of a public key. Use PeacemakrKey_new_pem_priv
 * to generate a private key from a pre-created pem file. Uses \p cfg to
 * configure the key being created. \returns A newly created peacemakr key
 * for use in other library calls.
 */
peacemakr_key_t *PeacemakrKey_new_pem_pub(crypto_config_t cfg, const char *buf,
                                          size_t buflen);

/**
 * Create a new peacemakr_key_t from a pem file generated externally. This
 * function applies only to asymmetric encryption provided by this library,
 * and the pem file must be of a private key. Use PeacemakrKey_new_pem_pub
 * to generate a public key from a pre-created pem file. Uses \p cfg to
 * configure the key being created. \returns A newly created peacemakr key
 * for use in other library calls.
 */
peacemakr_key_t *PeacemakrKey_new_pem_priv(crypto_config_t cfg, const char *buf,
                                           size_t buflen);

/**
 * Gets the crypto_config_t used to create \p key from \p key.
 */
crypto_config_t PeacemakrKey_get_config(const peacemakr_key_t *key);

/**
 * Free \p key. Attempts to securely clear all memory associated with \p key.
 */
void PeacemakrKey_free(peacemakr_key_t *key);

/**
 * Performs the encryption operation using the configuration and
 * the (symmetric or asymmetric) key in \p key. The operation is performed
 * over \p plain and uses \p rand to generate the IV/nonce. Returns a
 * ciphertext_blob_t that can be used in calls to uint8_t
 * *serialize_blob(ciphertext_blob_t *, size_t *) and bool
 * peacemakr_decrypt(const peacemakr_key_t *, ciphertext_blob_t *, plaintext_t
 * *)
 */
ciphertext_blob_t *peacemakr_encrypt(const peacemakr_key_t *key,
                                     const plaintext_t *plain,
                                     random_device_t *rand);

/**
 * Performs the decryption operation using the configuration and
 * the (symmetric or asymmetric) key in \p key. The operation is performed
 * over \p cipher and the result is stored in \p plain. Returns a
 * boolean to indicate if decryption was successful.
 */
bool peacemakr_decrypt(const peacemakr_key_t *key, ciphertext_blob_t *cipher,
                       plaintext_t *plain);

/**
 * Serializes \p cipher into a \return Base64 encoded buffer. Stores the size of
 * said buffer into \p out_size. The caller is responsible for managing
 * memory returned from this function.
 */
uint8_t *serialize_blob(ciphertext_blob_t *cipher, size_t *out_size);

/**
 * Deserializes a ciphertext_blob_t from \p b64_encoded_cipher. \p
 * serialized_len must be the same as out_size from uint8_t
 * *serialize_blob(ciphertext_blob_t *, size_t *). \returns A ciphertext_blob_t
 * that may be passed to bool peacemakr_decrypt(const peacemakr_key_t *,
 * ciphertext_blob_t *, plaintext_t *)
 */
ciphertext_blob_t *deserialize_blob(const uint8_t *b64_serialized_cipher,
                                    size_t serialized_len);

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTO_H
