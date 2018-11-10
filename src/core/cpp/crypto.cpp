//
// Created by Aman LaChapelle on 9/1/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "crypto.hpp"

#include <cassert>
#include <cstdio>
#include <stdexcept>

peacemakr::RandomDevice::RandomDevice(rng_buf generator, rng_err err_handler)
    : m_rand_{.generator = generator, .err = err_handler} {}

peacemakr::RandomDevice peacemakr::RandomDevice::getDefault() {
  return {[](unsigned char *buf, size_t num) -> int {
            arc4random_buf((void *)buf, num);
            return 0;
          },
          [](int err) -> const char * { return ""; }};
}

random_device_t &peacemakr::RandomDevice::getContents() { return m_rand_; }

peacemakr::Key::Key(crypto_config_t cfg, peacemakr::RandomDevice &rand) {
  m_key_ = PeacemakrKey_new(cfg, &rand.getContents());
}

peacemakr::Key::Key(crypto_config_t cfg, const uint8_t *bytes,
                    const size_t num) {
  m_key_ = PeacemakrKey_new_bytes(cfg, bytes, num);
}

peacemakr::Key::Key(crypto_config_t cfg, const std::vector<uint8_t> &bytes) {
  m_key_ = PeacemakrKey_new_bytes(cfg, bytes.data(), bytes.size());
}

peacemakr::Key::Key(crypto_config_t cfg, const peacemakr::Key &master,
                    const uint8_t *bytes, const size_t num) {
  m_key_ = PeacemakrKey_new_from_master(cfg, master.m_key_, bytes, num);
}

peacemakr::Key::Key(crypto_config_t cfg, const peacemakr::Key &master,
                    const std::vector<uint8_t> &bytes) {
  m_key_ = PeacemakrKey_new_from_master(cfg, master.m_key_, bytes.data(),
                                        bytes.size());
}

peacemakr::Key::Key(crypto_config_t cfg, const std::string &pem, bool priv) {
  if (priv)
    m_key_ = PeacemakrKey_new_pem_priv(cfg, pem.c_str(), pem.size());
  else
    m_key_ = PeacemakrKey_new_pem_pub(cfg, pem.c_str(), pem.size());
}

peacemakr::Key::~Key() { PeacemakrKey_free(m_key_); }

crypto_config_t peacemakr::Key::getConfig() const {
  return PeacemakrKey_get_config(m_key_);
}

const peacemakr_key_t *peacemakr::Key::getKey() const { return m_key_; }

bool peacemakr::Key::isValid() const { return m_key_ != nullptr; }

namespace {
void setContents(peacemakr::Plaintext &plain, plaintext_t &cstyle) {
  if (cstyle.data != nullptr) {
    plain.data = std::string(cstyle.data, cstyle.data + cstyle.data_len);
    free((void *)cstyle.data);
    cstyle.data = nullptr;
    cstyle.data_len = 0;
  }
  if (cstyle.aad != nullptr) {
    plain.aad = std::string(cstyle.aad, cstyle.aad + cstyle.aad_len);
    free((void *)cstyle.aad);
    cstyle.aad = nullptr;
    cstyle.aad_len = 0;
  }
}
} // namespace

peacemakr::CryptoContext::CryptoContext(LogFunctionType logger)
    : m_log_(std::move(logger)) {
  if (!peacemakr_init()) {
    m_log_("Unable to properly start the random device");
  }
}

namespace {
void log(const std::string &msg) { printf("%s", msg.c_str()); }
} // namespace

peacemakr::CryptoContext::CryptoContext() : m_log_(log) {
  if (!peacemakr_init()) {
    m_log_("Unable to properly start the random device");
  }
}

std::string peacemakr::CryptoContext::Encrypt(
    const peacemakr::Key &key, const peacemakr::Plaintext &plaintext,
    peacemakr::RandomDevice &rand, bool sign, const Key *sender_key) {
  // Early exit if the key is invalid
  if (!key.isValid()) {
    m_log_("invalid key in Encrypt");
    return "";
  }
  
  plaintext_t plain = {
      .data = plaintext.data.empty()
              ? nullptr
              : (const unsigned char *)plaintext.data.c_str(),
      .data_len = plaintext.data.empty() ? 0 : (size_t)plaintext.data.size(),
      .aad = plaintext.aad.empty()
                 ? nullptr
                 : (const unsigned char *)plaintext.aad.c_str(),
      .aad_len = plaintext.aad.empty() ? 0 : (size_t)plaintext.aad.size()};

  const peacemakr_key_t *pmKey = key.getKey();

  ciphertext_blob_t *blob =
      peacemakr_encrypt(pmKey, &plain, &rand.getContents());
  if (blob == nullptr) {
    m_log_("encryption failed");
    return "";
  }

  if (sign) {
    if (key.getConfig().mode == ASYMMETRIC) {
      if (sender_key == nullptr || !sender_key->isValid()) {
        m_log_("Invalid sender key for asymmetric signing of a message");
        return "";
      }
      peacemakr_sign(sender_key->getKey(), &plain, blob);
    } else if (key.getConfig().mode == SYMMETRIC) {
      peacemakr_sign(key.getKey(), &plain, blob);
    }
  }

  size_t out_size = 0;
  uint8_t *serialized = serialize_blob(blob, &out_size);

  return std::string(serialized, serialized + out_size);
}

peacemakr::Plaintext
peacemakr::CryptoContext::ExtractUnverifiedAAD(const std::string &serialized) {
  // Early exit if there is nothing to decrypt
  if (serialized.empty()) {
    m_log_("nothing to decrypt");
    return Plaintext{};
  }

  ciphertext_blob_t *blob =
      deserialize_blob((unsigned char *)serialized.c_str(), serialized.size());

  plaintext_t out;
  bool success = peacemakr_decrypt(nullptr, blob, &out, false);
  if (!success) {
    m_log_("extract failed");
    return Plaintext{};
  }

  Plaintext plain;
  setContents(plain, out);

  return plain;
}

peacemakr::Plaintext
peacemakr::CryptoContext::Decrypt(const peacemakr::Key &key,
                                  const std::string &serialized, bool verify,
                                  const Key *sender_key) {

  // Early exit if there is nothing to decrypt
  if (serialized.empty()) {
    m_log_("noting to decrypt");
    return Plaintext{};
  }

  ciphertext_blob_t *blob =
      deserialize_blob((unsigned char *)serialized.c_str(), serialized.size());

  plaintext_t out;
  bool success = peacemakr_decrypt(key.getKey(), blob, &out, verify);
  if (!success) {
    m_log_("decryption failed");
    return Plaintext{};
  }

  if (verify) {
    if (key.getConfig().mode == ASYMMETRIC) {
      if (sender_key == nullptr || !sender_key->isValid()) {
        m_log_("Invalid sender key for asymmetric signing of a message");
        return {};
      }
      success &= peacemakr_verify(sender_key->getKey(), &out, blob);
    } else if (key.getConfig().mode == SYMMETRIC) {
      success &= peacemakr_verify(key.getKey(), &out, blob);
    }
  }

  Plaintext plain{};
  if (success) {
    setContents(plain, out);
  }

  return plain;
}
