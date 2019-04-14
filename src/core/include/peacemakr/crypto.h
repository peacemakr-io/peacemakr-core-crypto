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
#include <stdio.h>

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
  AES_128_GCM = 0,
  AES_192_GCM = 1,
  AES_256_GCM = 2,
  CHACHA20_POLY1305 = 3,
} symmetric_cipher;

/**
 * @brief Peacemakr supported asymmetric cipher algorithms
 *
 * The two RSA modes can be used for actual asymmetric encrypt/decrypt
 * operations The ECDH mode may only be used for performing ECDH key exchanges
 * and encrypting with the derived key.
 */
typedef enum {
  NONE = 0,
  RSA_2048 = 1,
  RSA_4096 = 2,
  ECDH_P256 = 3,
  ECDH_P384 = 4,
  ECDH_P521 = 5,
} asymmetric_cipher;

/**
 * @brief Peacemakr supported message digest algorithms
 *
 * We actually technically support most any of the OpenSSL digest algorithms.
 * However, many of them are insecure or have collisions, so we have selected
 * the ones that are considered to be secure.
 */
typedef enum {
  SHA_224 = 0,
  SHA_256 = 1,
  SHA_384 = 2,
  SHA_512 = 3,
} message_digest_algorithm;

/**
 * @brief Peacemakr supported encryption modes
 */
typedef enum { SYMMETRIC, ASYMMETRIC } encryption_mode;

/**
 * @brief Configures the crypto library calls
 *
 * Uses the above enums to configure the library calls so that the encryption is
 * performed as required. Held inside peacemakr_key_t objects so that the key
 * is guaranteed to be suitable for the configuration.
 */
typedef struct {
  encryption_mode mode;

  //! Our asymmetric cryptography always uses symmetric crypto to
  //! encrypt the actual message (either by generating a shared secret
  //! or by encrypting a symmetric key) so this is always required.
  symmetric_cipher symm_cipher;

  asymmetric_cipher asymm_cipher;

  message_digest_algorithm digest_algorithm;
} crypto_config_t;

/**
 * @brief Convenience data structure for holding plaintext and AAD
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
//! save for the key itself
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
 * Logging callback that takes a C string and does something with it.
 * The library calls this function with any log messages in order to pass
 * them up to the user.
 */
typedef void (*peacemakr_log_cb)(const char *);

/**
 * Sets peacemakr logging utilities to use \p log_fn as a callback to return
 * log messages upstream.
 */
void peacemakr_set_log_callback(peacemakr_log_cb log_fn);

/**
 * Create a new peacemakr_key_t from scratch with user-defined \p cfg and \p
 * rand to configure the key creation. It is recommended that \p rand come from
 * /dev/urandom or similar. \returns A newly created peacemakr key for use in
 * other library calls.
 */
peacemakr_key_t *peacemakr_key_new(crypto_config_t cfg, random_device_t *rand);

/**
 * Create a new peacemakr_key_t from bytes generated externally. This
 * function applies only to symmetric encryption provided by this library.
 * Uses \p cfg to configure the key being created. Stores \p buf for use as
 * a symmetric key - it is recommended that these come from /dev/urandom or
 * similar. \returns A newly created peacemakr key for use in other library
 * calls.
 */
peacemakr_key_t *peacemakr_key_new_bytes(crypto_config_t cfg,
                                         const uint8_t *buf,
                                         const size_t buf_len);

/**
 * Computes a symmetric key specified by \p cfg according to PKCS5. We
 * use a PBKDF2_HMAC construction from OpenSSL that operates on \p password
 * for \p iteration_count times, using \p salt.
 */
peacemakr_key_t *peacemakr_key_new_from_password(
    crypto_config_t cfg, const uint8_t *password, const size_t password_len,
    const uint8_t *salt, const size_t salt_len, const size_t iteration_count);

/**
 * Create a new peacemakr_key_t from a master key generated by the peacemakr key
 * generator or through an external API. Uses a counter mode KDF as described in
 * NIST SP 800-180 with \p key_id on \p master_key to create a new key that can
 * be used in further cryptographic endeavors.
 */
peacemakr_key_t *
peacemakr_key_new_from_master(crypto_config_t cfg,
                              const peacemakr_key_t *master_key,
                              const uint8_t *key_id, const size_t key_id_len);

/**
 * Create a new peacemakr_key_t from a pem file generated externally. This
 * function applies only to asymmetric encryption provided by this library,
 * and the pem file must be of a public key. Uses \p cfg to configure
 * the key being created. \returns A newly created peacemakr key for use
 * in other library calls.
 */
peacemakr_key_t *peacemakr_key_new_pem_pub(crypto_config_t cfg, const char *buf,
                                           size_t buflen);

/**
 * Create a new peacemakr_key_t from a pem file generated externally. This
 * function applies only to asymmetric encryption provided by this library,
 * and the pem file must be of a private key. Uses \p cfg to configure
 * the key being created. \returns A newly created peacemakr key for use
 * in other library calls.
 */
peacemakr_key_t *peacemakr_key_new_pem_priv(crypto_config_t cfg,
                                            const char *buf, size_t buflen);

/**
 * Create a new symmetric peacemakr_key_t using a Diffie-Hellman exchange
 * between \p my_key (which is a private key) and \p peer_key (which is a public
 * key)
 */
peacemakr_key_t *peacemakr_key_dh_generate(peacemakr_key_t *my_key,
                                           peacemakr_key_t *peer_key);

/**
 * Gets the crypto_config_t used to create \p key from \p key.
 */
crypto_config_t peacemakr_key_get_config(const peacemakr_key_t *key);

/**
 * Serializes private key \p key into \p buf in PEM format and places its size
 * into \p bufsize. The caller is responsible for memory returned from this
 * function via \p buf.
 */
bool peacemakr_key_priv_to_pem(const peacemakr_key_t *key, char **buf,
                               size_t *bufsize);

/**
 * @copydoc PeacemakrKey_priv_to_pem
 */
bool peacemakr_key_pub_to_pem(const peacemakr_key_t *key, char **buf,
                              size_t *bufsize);

/**
 * Copies the bytes of \p key into \p buf and copies the size of \p buf into \p
 * bufsize.
 */
bool peacemakr_key_get_bytes(const peacemakr_key_t *key, uint8_t **buf,
                             size_t *bufsize);

/**
 * Free \p key. Attempts to securely clear all memory associated with \p key.
 */
void peacemakr_key_free(peacemakr_key_t *key);

/**
 * Free ciphertext blob objects. Will need to be called very rarely,
 * the FFI should handle this.
 */
void ciphertext_blob_free(ciphertext_blob_t *ciphertext);

/**
 * Performs the encryption operation using the configuration and the (symmetric
 * or asymmetric) key in \p recipient_key. The operation is
 * performed over \p plain and uses \p rand to generate the IV/nonce. Returns a
 * ciphertext_blob_t that can be used in calls to peacemakr_sign,
 * peacemakr_serialize, peacemakr_decrypt, and peacemakr_verify
 */
ciphertext_blob_t *peacemakr_encrypt(const peacemakr_key_t *recipient_key,
                                     const plaintext_t *plain,
                                     random_device_t *rand);

/**
 * Signs the plaintext in \p plain with key \p sender_key. If the configuration
 * in \p sender_key is SYMMETRIC then this method stores an HMAC in \p cipher.
 * If the configuration is ASYMMETRIC then this method uses the EVP_DigestSign*
 * functions to do asymmetric signing of \p plain and stores it in \p cipher.
 */
void peacemakr_sign(const peacemakr_key_t *sender_key, const plaintext_t *plain,
                    ciphertext_blob_t *cipher);

//! Possible decrypt outcomes
typedef enum {
  DECRYPT_SUCCESS = 0,
  DECRYPT_NEED_VERIFY = 1,
  DECRYPT_FAILED = 2,
} decrypt_code;

/**
 * Performs the decryption operation using the configuration and the (symmetric
 * or asymmetric) key in \p recipient_key. The operation is performed over \p
 * cipher and the result is stored in \p plain. \returns a code to indicate if
 * verify needs to be called on the result of decryption, if decrypt succeeded
 * outright, or if decrypt failed.
 */
decrypt_code peacemakr_decrypt(const peacemakr_key_t *recipient_key,
                               ciphertext_blob_t *cipher, plaintext_t *plain);

/**
 * Attempts to extract any AAD from the message.
 * Note that this AAD is unconfirmed and may have been tampered with.
 */
bool peacemakr_get_unverified_aad(ciphertext_blob_t *cipher,
                                  plaintext_t *plain);

/**
 * Verifies the plaintext in \p plain with key \p sender_key. If the
 * configuration in \p sender_key is SYMMETRIC then this method compares a
 * computed HMAC against the one in \p cipher. If the configuration is
 * ASYMMETRIC then this method uses the EVP_DigestVerify* functions to do
 * asymmetric verification of \p plain against the signature in \p cipher.
 * \returns false if verification is unsuccessful.
 */
bool peacemakr_verify(const peacemakr_key_t *sender_key,
                      const plaintext_t *plain, ciphertext_blob_t *cipher);

/**
 * Computes the HMAC of \p buf with \p master_key. Allocates memory and
 * returns it to the caller with the HMAC stored inside.
 */
uint8_t *peacemakr_hmac(const message_digest_algorithm digest_algorithm,
                        const peacemakr_key_t *master_key, const uint8_t *buf,
                        const size_t buf_len, size_t *out_bytes);

/**
 * Serializes \p cipher into a \return Base64 encoded buffer. Stores the size of
 * said buffer into \p out_size. The caller is responsible for managing
 * memory returned from this function.
 */
uint8_t *peacemakr_serialize(ciphertext_blob_t *cipher, size_t *b64_size);

/**
 * Deserializes a ciphertext_blob_t from \p b64_encoded_cipher. \p
 * serialized_len must be the same as out_size from uint8_t
 * *peacemakr_serialize(ciphertext_blob_t *, size_t *). \returns A
 * ciphertext_blob_t that may be passed to bool peacemakr_decrypt(const
 * peacemakr_key_t *, ciphertext_blob_t *, plaintext_t *)
 */
ciphertext_blob_t *peacemakr_deserialize(const uint8_t *b64_serialized_cipher,
                                         size_t b64_serialized_len,
                                         crypto_config_t *cfg);

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTO_H
