//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_KEY_HPP
#define PEACEMAKR_CORE_CRYPTO_KEY_HPP

extern "C" {
#include "crypto.h"

#ifdef linux
#include <bsd/stdlib.h>
#else
#include <stdlib.h>
#endif
};

#include <functional>
#include <string>
#include <vector>

/**
 * @file peacemakr/crypto.hpp
 * Peacemakr core crypto C++ bindings
 */

namespace peacemakr {
/**
 * @class RandomDevice
 *
 * Thin RAII wrapper around random_device_t for use from C++.
 */
class RandomDevice {
public:
  /**
   * Constructs a RandomDevice from a \p generator and \p err_handler.
   */
  RandomDevice(rng_buf generator, rng_err err_handler);

  /**
   * Construct a 'default' RandomDevice that reads from /dev/urandom.
   */
  static RandomDevice getDefault();

  /**
   * Convenience function for getting the internal random_device_t.
   */
  random_device_t &getContents();

private:
  random_device_t m_rand_;
};

/**
 * @class Key
 *
 * Thin RAII wrapper around peacemakr_key_t for use from C++.
 */
class Key {
public:
  /**
   * Constructors for Key corresponding to:
   * 1. peacemakr_key_t *PeacemakrKey_new(crypto_config_t, random_device_t *)
   * 2. peacemakr_key_t *PeacemakrKey_new_bytes(crypto_config_t, const uint8_t
   * *)
   * 3. peacemakr_key_t *PeacemakrKey_new_pem_pub(crypto_config_t, const char *,
   * size_t)
   * 4. peacemakr_key_t *PeacemakrKey_new_pem_priv(crypto_config_t, const char
   * *, size_t)
   *
   * 3 can be used by passing in \p priv as false, and 4 is with \p priv true.
   */
  //!\{
  Key(crypto_config_t cfg, RandomDevice &rand);
  Key(crypto_config_t cfg, const uint8_t *bytes, const size_t num);
  Key(crypto_config_t cfg, const std::vector<uint8_t> &bytes);
  Key(crypto_config_t cfg, const Key &master, const uint8_t *bytes,
      const size_t num);
  Key(crypto_config_t cfg, const Key &master,
      const std::vector<uint8_t> &bytes);
  Key(crypto_config_t cfg, const std::string &pem, bool priv);
  //!\}

  /**
   * Key is not copy or move constructible
   */
  Key(const Key &other) = delete;
  Key(Key &&other) = delete;

  /**
   * Clears memory associated with this, and cleans up.
   */
  ~Key();

  /**
   * Get the crypto_config_t used to construct this key.
   */
  crypto_config_t getConfig() const;

  /**
   * Check if this key is valid. Any number of errors can produce an invalid
   * key.
   */
  bool isValid() const;

  /**
   * Get the peacemakr_key_t internal representation for use with other crypto
   * lib calls.
   */
  const peacemakr_key_t *getKey() const;

private:
  peacemakr_key_t *m_key_;
};

/**
 * @class Plaintext
 *
 * Thin STL substitute for the plaintext_t struct used on the C side.
 */
struct Plaintext {
  std::string data;
  std::string aad;
};

typedef std::function<void(const std::string &)> LogFunctionType;

/**
 * @class CryptoContext
 *
 * The constructor for this class initializes the library, ensuring that the
 * csprng is properly seeded.
 */
class CryptoContext {
public:
  /**
   * Initializes the crypto library
   */
  explicit CryptoContext(LogFunctionType logger);
  /**
   * Initializes the crypto library that logs everything to the stdout.
   */
  CryptoContext();
  ~CryptoContext() = default;

  /**
   * Uses \p key and \p rand to encrypt \p plaintext and base64 serialize it.
   * \returns A string holding the B64 encoded, encrypted contents.
   */
  std::string Encrypt(const Key *recipient_key, const Key *sender_key, const Plaintext &plaintext,
                      RandomDevice &rand);

  Plaintext ExtractUnverifiedAAD(const std::string &serialized);

  /**
   * Deserializes \p serialized and decrypts it using \p key. \returns a
   * Plaintext object that holds the decrypted data and the AAD (if any exists).
   */
  Plaintext Decrypt(const Key *recipient_key, const Key *sender_key, const std::string &serialized);

private:
  LogFunctionType m_log_;
};
}; // namespace peacemakr

#endif // PEACEMAKR_CORE_CRYPTO_KEY_HPP
