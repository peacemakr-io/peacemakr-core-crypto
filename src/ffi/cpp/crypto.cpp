//
// Created by Aman LaChapelle on 9/1/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "peacemakr/crypto.hpp"

#include <cstring>

peacemakr::RandomDevice::RandomDevice(rng_buf generator, rng_err err_handler)
    : m_rand_{.generator = generator, .err = err_handler} {}

peacemakr::RandomDevice::RandomDevice()
    : m_rand_(get_default_random_device()) {}

random_device_t &peacemakr::RandomDevice::getContents() { return m_rand_; }

peacemakr::Key::Key(asymmetric_cipher asymm_cipher,
                    symmetric_cipher symm_cipher,
                    peacemakr::RandomDevice &rand) {
  m_key_ = peacemakr_key_new_asymmetric(asymm_cipher, symm_cipher,
                                        &rand.getContents());
}

peacemakr::Key::Key(symmetric_cipher symm_cipher,
                    peacemakr::RandomDevice &rand) {
  m_key_ = peacemakr_key_new_symmetric(symm_cipher, &rand.getContents());
}

peacemakr::Key::Key(symmetric_cipher cipher, const uint8_t *bytes,
                    const size_t num) {
  m_key_ = peacemakr_key_new_bytes(cipher, bytes, num);
}

peacemakr::Key::Key(symmetric_cipher cipher,
                    const std::vector<uint8_t> &bytes) {
  m_key_ = peacemakr_key_new_bytes(cipher, bytes.data(), bytes.size());
}

peacemakr::Key::Key(symmetric_cipher cipher, const std::string &bytes) {
  // If the key size is small it's probably a symmetric key, otherwise it's
  // probably a PEM file
  if (bytes.size() <= 32) {
    m_key_ =
        peacemakr_key_new_bytes(cipher, (uint8_t *)bytes.data(), bytes.size());
  } else {
    m_key_ = peacemakr_key_new_pem_priv(cipher, bytes.c_str(), bytes.size());
  }
}

peacemakr::Key::Key(symmetric_cipher cipher, message_digest_algorithm digest,
                    const uint8_t *password, const size_t password_len,
                    const uint8_t *salt, const size_t salt_len,
                    const size_t iteration_count) {
  m_key_ = peacemakr_key_new_from_password(
      cipher, digest, password, password_len, salt, salt_len, iteration_count);
}

peacemakr::Key::Key(symmetric_cipher cipher, message_digest_algorithm digest,
                    const std::vector<uint8_t> &password,
                    const std::vector<uint8_t> &salt,
                    const size_t iteration_count) {
  m_key_ = peacemakr_key_new_from_password(cipher, digest, password.data(),
                                           password.size(), salt.data(),
                                           salt.size(), iteration_count);
}

peacemakr::Key::Key(symmetric_cipher cipher, message_digest_algorithm digest,
                    const std::string &password, const std::string &salt,
                    const size_t iteration_count) {
  m_key_ = peacemakr_key_new_from_password(
      cipher, digest, (uint8_t *)password.data(), password.size(),
      (uint8_t *)salt.data(), salt.size(), iteration_count);
}

peacemakr::Key::Key(symmetric_cipher cipher, message_digest_algorithm digest,
                    const peacemakr::Key &master, const uint8_t *bytes,
                    const size_t bytes_len) {
  m_key_ = peacemakr_key_new_from_master(cipher, digest, master.m_key_, bytes,
                                         bytes_len);
}

peacemakr::Key::Key(symmetric_cipher cipher, message_digest_algorithm digest,
                    const Key &master, const std::vector<uint8_t> &bytes) {
  m_key_ = peacemakr_key_new_from_master(cipher, digest, master.m_key_,
                                         bytes.data(), bytes.size());
}

peacemakr::Key::Key(symmetric_cipher cipher, message_digest_algorithm digest,
                    const Key &master, const std::string &bytes) {
  m_key_ = peacemakr_key_new_from_master(cipher, digest, master.m_key_,
                                         (uint8_t *)bytes.data(), bytes.size());
}

peacemakr::Key::Key(symmetric_cipher symm_cipher, const std::string &pem,
                    const std::string &truststore_path) {
  m_key_ = peacemakr_key_new_pem_pub(symm_cipher, pem.c_str(), pem.size(),
                                     truststore_path.c_str(),
                                     truststore_path.size());
}

peacemakr::Key::Key(symmetric_cipher cipher, const peacemakr::Key &my_key,
                    const peacemakr::Key &peer_key) {
  m_key_ = peacemakr_key_dh_generate(cipher, my_key.m_key_, peer_key.m_key_);
}

peacemakr::Key::~Key() { peacemakr_key_free(m_key_); }

crypto_config_t peacemakr::Key::getConfig() const {
  return peacemakr_key_get_config(m_key_);
}

bool peacemakr::Key::isValid() const { return m_key_ != nullptr; }

std::string peacemakr::Key::getCSR(const std::string &org,
                                   const std::string &cn) const {
  uint8_t *buf;
  size_t bufsize;
  bool success = peacemakr_key_generate_csr(m_key_, (uint8_t *)org.data(),
                                            org.size(), (uint8_t *)cn.data(),
                                            cn.size(), &buf, &bufsize);
  if (!success) {
    return "";
  }

  return std::string(buf, buf + bufsize);
}

bool peacemakr::Key::addCertificate(const std::string &pem) {
  return peacemakr_key_add_certificate(m_key_, (const uint8_t *)pem.data(),
                                       pem.size());
}

std::string peacemakr::Key::getPrivPem() const {
  char *buf;
  size_t bufsize;
  bool success = peacemakr_key_priv_to_pem(m_key_, &buf, &bufsize);
  if (!success) {
    return "";
  }

  return std::string(buf, buf + bufsize);
}

std::string peacemakr::Key::getPubPem() const {
  char *buf;
  size_t bufsize;
  bool success = peacemakr_key_pub_to_pem(m_key_, &buf, &bufsize);
  if (!success) {
    return "";
  }

  return std::string(buf, buf + bufsize);
}

std::string peacemakr::Key::getCertificate() const {
  char *buf;
  size_t bufsize;
  bool success = peacemakr_key_to_certificate(m_key_, &buf, &bufsize);
  if (!success) {
    return "";
  }

  return std::string(buf, buf + bufsize);
}

std::string peacemakr::Key::getBytes() const {
  uint8_t *buf;
  size_t bufsize;
  bool success = peacemakr_key_get_bytes(m_key_, &buf, &bufsize);

  if (!success) {
    return {};
  }

  return std::string(buf, buf + bufsize);
}

const peacemakr_key_t *peacemakr::Key::getKey() const { return m_key_; }

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
void log_msg(const std::string &msg) { printf("%s", msg.c_str()); }
} // namespace

peacemakr::CryptoContext::CryptoContext() : m_log_(log_msg) {
  peacemakr_set_log_callback([](const char *msg) {
    log_msg({msg, msg + strlen(msg)});
  });

  if (!peacemakr_init()) {
    m_log_("Unable to properly start the random device");
  }
}

peacemakr::Ciphertext
peacemakr::CryptoContext::Encrypt(const Key &key, const Plaintext &plaintext,
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

peacemakr::Ciphertext
peacemakr::CryptoContext::GetPlaintextBlob(const Plaintext &plaintext) {
  plaintext_t plain = {
      .data = plaintext.data.empty()
                  ? nullptr
                  : (const unsigned char *)plaintext.data.c_str(),
      .data_len = plaintext.data.empty() ? 0 : (size_t)plaintext.data.size(),
      .aad = plaintext.aad.empty()
                 ? nullptr
                 : (const unsigned char *)plaintext.aad.c_str(),
      .aad_len = plaintext.aad.empty() ? 0 : (size_t)plaintext.aad.size()};
  ciphertext_blob_t *blob = peacemakr_get_plaintext_blob(&plain);
  return blob;
}

peacemakr::Plaintext peacemakr::CryptoContext::ExtractPlaintextBlob(
    peacemakr::Ciphertext const blob) {

  plaintext_t out;
  bool success =
      peacemakr_extract_plaintext_blob((ciphertext_blob_t *)blob, &out);
  if (!success) {
    m_log_("extraction failed");
    return Plaintext{};
  }

  Plaintext plain{};
  setContents(plain, out);

  return plain;
}

bool peacemakr::CryptoContext::Sign(const peacemakr::Key &senderKey,
                                    const peacemakr::Plaintext &plaintext,
                                    message_digest_algorithm digest,
                                    Ciphertext blob) {

  plaintext_t plain = {
      .data = plaintext.data.empty()
                  ? nullptr
                  : (const unsigned char *)plaintext.data.c_str(),
      .data_len = plaintext.data.empty() ? 0 : (size_t)plaintext.data.size(),
      .aad = plaintext.aad.empty()
                 ? nullptr
                 : (const unsigned char *)plaintext.aad.c_str(),
      .aad_len = plaintext.aad.empty() ? 0 : (size_t)plaintext.aad.size()};

  return peacemakr_sign(senderKey.getKey(), &plain, digest,
                        (ciphertext_blob_t *)blob);
}

std::string peacemakr::CryptoContext::Serialize(message_digest_algorithm digest,
                                                Ciphertext blob) {
  size_t out_size = 0;
  uint8_t *serialized =
      peacemakr_serialize(digest, (ciphertext_blob_t *)blob, &out_size);
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
  ciphertext_blob_free(blob);

  if (!success) {
    m_log_("extract failed");
    return Plaintext{};
  }

  Plaintext plain;
  setContents(plain, out);

  return plain;
}

std::pair<peacemakr::Ciphertext, crypto_config_t>
peacemakr::CryptoContext::Deserialize(const std::string &serialized) {
  crypto_config_t out_cfg;

  if (serialized.empty()) {
    m_log_("noting to deserialize");
    return {nullptr, crypto_config_t{}};
  }
  ciphertext_blob_t *deserialized = peacemakr_deserialize(
      (uint8_t *)serialized.data(), serialized.size(), &out_cfg);

  return {deserialized, out_cfg};
}

std::pair<peacemakr::Plaintext, bool>
peacemakr::CryptoContext::Decrypt(const Key &key, peacemakr::Ciphertext blob) {

  plaintext_t out;
  decrypt_code success =
      peacemakr_decrypt(key.getKey(), (ciphertext_blob_t *)blob, &out);
  bool needVerify = false;
  switch (success) {
  case DECRYPT_SUCCESS:
    break;
  case DECRYPT_NEED_VERIFY:
    needVerify = true;
    break;
  case DECRYPT_FAILED: {
    m_log_("decryption failed");
    return {Plaintext{}, false};
  }
  }

  Plaintext plain{};
  setContents(plain, out);

  return {plain, needVerify};
}

bool peacemakr::CryptoContext::Verify(const peacemakr::Key &senderKey,
                                      const peacemakr::Plaintext &plain,
                                      Ciphertext blob) {
  plaintext_t cplain = {
      .data = plain.data.empty() ? nullptr
                                 : (const unsigned char *)plain.data.c_str(),
      .data_len = plain.data.empty() ? 0 : (size_t)plain.data.size(),
      .aad = plain.aad.empty() ? nullptr
                               : (const unsigned char *)plain.aad.c_str(),
      .aad_len = plain.aad.empty() ? 0 : (size_t)plain.aad.size()};

  return peacemakr_verify(senderKey.getKey(), &cplain,
                          (ciphertext_blob_t *)blob);
}
