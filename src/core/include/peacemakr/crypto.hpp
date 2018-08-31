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
    RandomDevice(rng_buf generator, rng_err err_handler) : m_rand_{.generator = generator, .err = err_handler} {}

    static RandomDevice getDefault() {
      return {
        [](unsigned char *buf, size_t num) -> int {
          arc4random_buf((void *) buf, num);
          return 0;
        },
        [](int err) -> const char * { return ""; }
      };
    }

    random_device_t &getContents() {
      return m_rand_;
    }

  private:
    random_device_t m_rand_;
  };

  class Key {
  public:
    Key(crypto_config_t cfg, RandomDevice &rand) {
      m_key_ = PeacemakrKey_new(cfg, &rand.getContents());
    }

    Key(crypto_config_t cfg, const uint8_t *bytes) {
      m_key_ = PeacemakrKey_new_bytes(cfg, bytes);
    }

    Key(crypto_config_t cfg, const std::vector<uint8_t> &bytes) {
      m_key_ = PeacemakrKey_new_bytes(cfg, bytes.data());
    }

    Key(crypto_config_t cfg, const std::string &pem, bool priv) {
      if (priv) {
        m_key_ = PeacemakrKey_new_pem_priv(cfg, pem.c_str(), pem.size());
      }
      else {
        m_key_ = PeacemakrKey_new_pem_pub(cfg, pem.c_str(), pem.size());
      }
    }

    Key(const Key &other) = delete;
    Key(Key &&other) = delete;

    ~Key() {
      PeacemakrKey_free(m_key_);
    }

    crypto_config_t getConfig() {
      return PeacemakrKey_get_config(m_key_);
    }

    const peacemakr_key_t *getKey() const {
      return m_key_;
    }

  private:
    peacemakr_key_t *m_key_;
  };

  struct Plaintext {
    std::string data;
    std::string aad;

    void setContents(const plaintext_t &cstyle) {
      this->data = std::string(cstyle.data, cstyle.data + cstyle.data_len);
      this->aad = std::string(cstyle.aad, cstyle.aad + cstyle.aad_len);
    }
  };

  class CryptoContext {
  public:
    CryptoContext() = default; // when the initialization pr gets merged we will do the init here
    ~CryptoContext() {};

    std::string Encrypt(crypto_config_t cfg, const Key &key, const Plaintext &plaintext, RandomDevice &rand) {
      plaintext_t plain = {
              .data = (const unsigned char *)plaintext.data.c_str(),
              .data_len = (size_t)plaintext.data.size(),
              .aad = (const unsigned char *)plaintext.aad.c_str(),
              .aad_len = (size_t)plaintext.aad.size()
      };

      ciphertext_blob_t *blob = peacemakr_encrypt(cfg, key.getKey(), &plain, &rand.getContents());

      size_t out_size = 0;
      uint8_t *serialized = serialize_blob(blob, &out_size);

      return std::string(serialized, serialized+out_size);
    }

    Plaintext Decrypt(const Key &key, std::string &serialized) {
      ciphertext_blob_t *blob = deserialize_blob((unsigned char *)serialized.c_str(), serialized.size());

      plaintext_t out;
      bool success = peacemakr_decrypt(key.getKey(), blob, &out);

      Plaintext plain;
      plain.setContents(out);

      return plain;
    }
  };
};

#endif //PEACEMAKR_CORE_CRYPTO_KEY_HPP
