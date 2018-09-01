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

#include <vector>
#include <string>

namespace peacemakr {
  class RandomDevice {
  public:
    RandomDevice(rng_buf generator, rng_err err_handler);

    static RandomDevice getDefault();

    random_device_t &getContents();

  private:
    random_device_t m_rand_;
  };

  class Key {
  public:
    Key(crypto_config_t cfg, RandomDevice &rand);

    Key(crypto_config_t cfg, const uint8_t *bytes);

    Key(crypto_config_t cfg, const std::vector<uint8_t> &bytes);

    Key(crypto_config_t cfg, const std::string &pem, bool priv);

    Key(const Key &other) = delete;
    Key(Key &&other) = delete;

    ~Key();

    crypto_config_t getConfig();

    const peacemakr_key_t *getKey() const;

  private:
    peacemakr_key_t *m_key_;
  };

  struct Plaintext {
    std::string data;
    std::string aad;

    void setContents(const plaintext_t &cstyle);
  };

  class CryptoContext {
  public:
    CryptoContext() = default; // when the initialization pr gets merged we will do the init here
    ~CryptoContext() = default;

    std::string Encrypt(crypto_config_t cfg, const Key &key, const Plaintext &plaintext, RandomDevice &rand);

    Plaintext Decrypt(const Key &key, std::string &serialized);
  };
};

#endif //PEACEMAKR_CORE_CRYPTO_KEY_HPP
