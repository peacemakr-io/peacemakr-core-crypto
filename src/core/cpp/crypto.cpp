//
// Created by Aman LaChapelle on 9/1/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "crypto.hpp"

#include <stdexcept>

peacemakr::RandomDevice::RandomDevice(rng_buf generator, rng_err err_handler) : m_rand_{.generator = generator, .err = err_handler} {}

peacemakr::RandomDevice peacemakr::RandomDevice::getDefault() {
  return {
          [](unsigned char *buf, size_t num) -> int {
            arc4random_buf((void *) buf, num);
            return 0;
          },
          [](int err) -> const char * { return ""; }
  };
}

random_device_t &peacemakr::RandomDevice::getContents() {
  return m_rand_;
}

peacemakr::Key::Key(crypto_config_t cfg, peacemakr::RandomDevice &rand) {
  m_key_ = PeacemakrKey_new(cfg, &rand.getContents());
}

peacemakr::Key::Key(crypto_config_t cfg, const uint8_t *bytes) {
  m_key_ = PeacemakrKey_new_bytes(cfg, bytes);
}

peacemakr::Key::Key(crypto_config_t cfg, const std::vector<uint8_t> &bytes) {
  m_key_ = PeacemakrKey_new_bytes(cfg, bytes.data());
}

peacemakr::Key::Key(crypto_config_t cfg, const std::string &pem, bool priv) {
  if (priv) {
    m_key_ = PeacemakrKey_new_pem_priv(cfg, pem.c_str(), pem.size());
  }
  else {
    m_key_ = PeacemakrKey_new_pem_pub(cfg, pem.c_str(), pem.size());
  }
}

peacemakr::Key::~Key() {
  PeacemakrKey_free(m_key_);
}

crypto_config_t peacemakr::Key::getConfig() {
  return PeacemakrKey_get_config(m_key_);
}

const peacemakr_key_t *peacemakr::Key::getKey() const {
  return m_key_;
}

void peacemakr::Plaintext::setContents(const plaintext_t &cstyle) {
  this->data = std::string(cstyle.data, cstyle.data + cstyle.data_len);
  this->aad = std::string(cstyle.aad, cstyle.aad + cstyle.aad_len);
}

peacemakr::CryptoContext::CryptoContext() {
  if (!peacemakr_init()) {
    throw std::runtime_error("Unable to properly start the random device");
  }
}

std::string
peacemakr::CryptoContext::Encrypt(const peacemakr::Key &key, const peacemakr::Plaintext &plaintext,
                                  peacemakr::RandomDevice &rand) {
  plaintext_t plain = {
          .data = (const unsigned char *)plaintext.data.c_str(),
          .data_len = (size_t)plaintext.data.size(),
          .aad = (const unsigned char *)plaintext.aad.c_str(),
          .aad_len = (size_t)plaintext.aad.size()
  };

  ciphertext_blob_t *blob = peacemakr_encrypt(key.getKey(), &plain, &rand.getContents());

  size_t out_size = 0;
  uint8_t *serialized = serialize_blob(blob, &out_size);

  return std::string(serialized, serialized+out_size);
}

peacemakr::Plaintext peacemakr::CryptoContext::Decrypt(const peacemakr::Key &key, std::string &serialized) {
  ciphertext_blob_t *blob = deserialize_blob((unsigned char *)serialized.c_str(), serialized.size());

  plaintext_t out;
  bool success = peacemakr_decrypt(key.getKey(), blob, &out);

  Plaintext plain;
  plain.setContents(out);

  return plain;
}
