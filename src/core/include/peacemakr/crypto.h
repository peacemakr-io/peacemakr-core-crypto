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
 * @brief Create a new peacemakr_key_t from scratch using a user-defined secure
 * random source.
 * @param cfg The configuration for the cryptography calls - ensures that the
 * key is created correctly
 * @param rand User-defined random device. It is recommended that these come
 * from /dev/urandom or similar.
 * @return A newly created peacemakr key for use in other library calls
 */
peacemakr_key_t *PeacemakrKey_new(crypto_config_t cfg, random_device_t *rand);

/**
 * @brief Create a new peacemakr_key_t from bytes generated externally. This
 * does not apply for asymmetric encryption because OpenSSL generates its own
 * keypairs.
 * @param cfg The configuration for the cryptography calls - ensures that the
 * key is created correctly
 * @param buf The buffer of bytes allocated for encryption. It is recommended
 * that these come from /dev/urandom or similar.
 * @return A newly created peacemakr key for use in other library calls
 */
peacemakr_key_t *PeacemakrKey_new_bytes(crypto_config_t cfg,
                                        const uint8_t *buf);

/**
 * @brief Create a new peacemakr_key_t from an existing OpenSSL EVP_PKEY. This
 * does not apply for symmetric encryption.
 * @param cfg The configuration for the cryptography calls - ensures that the
 * key is created correctly
 * @param buf The previously initialized EVP_PKEY to copy into the
 * peacemakr_key_t.
 * @return A newly created peacemakr key for use in other library calls
 */
peacemakr_key_t *PeacemakrKey_new_pkey(crypto_config_t cfg,
                                       const EVP_PKEY *buf);

/**
 * @brief Free a peacemakr key. Clears all memory associated with the key.
 * @param key The key to free
 */
void PeacemakrKey_free(peacemakr_key_t *key);

/**
 * @brief Performs the encryption operation as configured by cfg, with key key
 * on plaintext plain, using random generator rand for iv generation. It is
 * recommended that the random generator hook up to /dev/urandom or similar.
 * @param cfg The configuration for the cryptography calls
 * @param key The key to use in the encryption process
 * @param plain The plaintext to encrypt
 * @param rand The random number generation unit to use
 * @return An opaque pointer to a blob that contains the encrypted message. This
 * can be passed to other peacemakr library calls, such as peacemakr_decrypt.
 */
ciphertext_blob_t *peacemakr_encrypt(crypto_config_t cfg,
                                     const peacemakr_key_t *key,
                                     const plaintext_t *plain,
                                     random_device_t *rand);

/**
 * @brief Performs the decryption operation of ciphertext cipher using key key
 * and stores its result in plaintext plain.
 * @param key The key that can decrypt the packet.
 * @param cipher
 * @param plain
 * @return
 */
bool peacemakr_decrypt(const peacemakr_key_t *key, ciphertext_blob_t *cipher,
                       plaintext_t *plain);

/**
 * @brief Serializes a ciphertext_blob_t cipher into a base64 encoded buffer of
 * uint8_t and stores the size of that buffer in out_size. Frees the
 * ciphertext_blob_t
 * @param cipher The ciphertext to serialize
 * @param out_size A non-null pointer to a size_t that will contain the size of
 * the buffer created by this function.
 * @return A byte buffer that is encoded in URL-safe base64.
 */
uint8_t *serialize_blob(ciphertext_blob_t *cipher, size_t *out_size);

/**
 * @brief Deserializes a previously serialized blob b64_serialized_cipher into a
 * ciphertext_blob_t for use in a decryption operation (for example).
 * @param b64_serialized_cipher The byte buffer created by a call to
 * serialize_blob
 * @param serialized_len The length of that buffer
 * @return A well-formed ciphertext_blob_t object that can be decrypted with the
 * appropriate key.
 */
ciphertext_blob_t *deserialize_blob(uint8_t *b64_serialized_cipher,
                                    size_t serialized_len);

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTO_H
