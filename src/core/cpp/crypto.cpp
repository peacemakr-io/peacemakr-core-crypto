//
// Created by Aman LaChapelle on 9/1/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "crypto.hpp"

#include <cstring>

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

peacemakr::Key::Key(const peacemakr::Key &my_key, const peacemakr::Key &peer) {
  m_key_ = PeacemakrKey_dh_generate(my_key.m_key_, peer.m_key_);
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

  peacemakr_set_log_callback([](const char *msg) { printf("%s", msg); });

  if (!peacemakr_init()) {
    m_log_("Unable to properly start the random device");
  }
}

namespace {
void log(const std::string &msg) { printf("%s", msg.c_str()); }
} // namespace

peacemakr::CryptoContext::CryptoContext() : m_log_(log) {
  peacemakr_set_log_callback([](const char *msg) {
    log({msg, msg + strlen(msg)});
  });

  if (!peacemakr_init()) {
    m_log_("Unable to properly start the random device");
  }
}

ciphertext_blob_t *peacemakr::CryptoContext::Encrypt(const Key &key,
                                                     const Plaintext &plaintext,
                                                     RandomDevice &rand) {
  // Early exit if the key is invalid
  if (!key.isValid()) {
    m_log_("invalid key in Encrypt");
    return nullptr;
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
  return blob;
}

void peacemakr::CryptoContext::Sign(const peacemakr::Key &senderKey,
                                    const peacemakr::Plaintext &plaintext,
                                    ciphertext_blob_t *blob) {

  plaintext_t plain = {
      .data = plaintext.data.empty()
                  ? nullptr
                  : (const unsigned char *)plaintext.data.c_str(),
      .data_len = plaintext.data.empty() ? 0 : (size_t)plaintext.data.size(),
      .aad = plaintext.aad.empty()
                 ? nullptr
                 : (const unsigned char *)plaintext.aad.c_str(),
      .aad_len = plaintext.aad.empty() ? 0 : (size_t)plaintext.aad.size()};

  return peacemakr_sign(senderKey.getKey(), &plain, blob);
}

std::string peacemakr::CryptoContext::Serialize(ciphertext_blob_t *blob) {
  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(blob, &out_size);
  std::string out{serialized, serialized + out_size};
  free(serialized);
  return out;
}

peacemakr::Plaintext
peacemakr::CryptoContext::ExtractUnverifiedAAD(const std::string &serialized) {
  // Early exit if there is nothing to decrypt
  if (serialized.empty()) {
    m_log_("nothing to extract from");
    return Plaintext{};
  }

  crypto_config_t out_cfg;

  ciphertext_blob_t *blob = peacemakr_deserialize(
      (unsigned char *)serialized.c_str(), serialized.size(), &out_cfg);

  plaintext_t out;
  bool success = peacemakr_get_unverified_aad(blob, &out);
  CiphertextBlob_free(blob);

  if (!success) {
    m_log_("extract failed");
    return Plaintext{};
  }

  Plaintext plain;
  setContents(plain, out);

  return plain;
}

ciphertext_blob_t *
peacemakr::CryptoContext::Deserialize(const std::string &serialized,
                                      crypto_config_t *out_cfg) {
  if (serialized.empty()) {
    m_log_("noting to deserialize");
    return nullptr;
  }
  return peacemakr_deserialize((uint8_t *)serialized.data(), serialized.size(),
                               out_cfg);
}

peacemakr::Plaintext peacemakr::CryptoContext::Decrypt(const Key &key,
                                                       ciphertext_blob_t *blob,
                                                       bool &needVerify) {

  plaintext_t out;
  decrypt_code success = peacemakr_decrypt(key.getKey(), blob, &out);
  switch (success) {
  case DECRYPT_SUCCESS:
    break;
  case DECRYPT_NEED_VERIFY:
    needVerify = true;
    break;
  case DECRYPT_FAILED: {
    m_log_("decryption failed");
    return Plaintext{};
  }
  }

  Plaintext plain{};
  setContents(plain, out);

  return plain;
}

bool peacemakr::CryptoContext::Verify(const peacemakr::Key &senderKey,
                                      const peacemakr::Plaintext &plain,
                                      ciphertext_blob_t *blob) {
  plaintext_t cplain = {
      .data = plain.data.empty() ? nullptr
                                 : (const unsigned char *)plain.data.c_str(),
      .data_len = plain.data.empty() ? 0 : (size_t)plain.data.size(),
      .aad = plain.aad.empty() ? nullptr
                               : (const unsigned char *)plain.aad.c_str(),
      .aad_len = plain.aad.empty() ? 0 : (size_t)plain.aad.size()};

  return peacemakr_verify(senderKey.getKey(), &cplain, blob);
}
