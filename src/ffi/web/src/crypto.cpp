//
// Copyright 2019 peacemakr
// Full license at peacemakr_core_crypto/LICENSE.txt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "peacemakr/crypto.hpp"
#include <emscripten.h>
#include <emscripten/bind.h>

namespace em = emscripten;

namespace peacemakr {
namespace js {

void logFn(const std::string &s) {
  em::val console = em::val::global("console");
  console.call<void>("log", s);
}

CryptoContext ctxFactory() { return CryptoContext(&js::logFn); }

auto newAsymm(asymmetric_cipher a, symmetric_cipher s, RandomDevice &r)
    -> std::unique_ptr<Key> {
  return std::make_unique<Key>(a, s, r);
}

auto newSymm(symmetric_cipher s, RandomDevice &r) -> std::unique_ptr<Key> {
  return std::make_unique<Key>(s, r);
}

auto fromBytes(symmetric_cipher s, const std::string &b)
    -> std::unique_ptr<Key> {
  return std::make_unique<Key>(s, b);
}

auto fromPem(symmetric_cipher s, const std::string &p, const std::string &t)
    -> std::unique_ptr<Key> {
  return std::make_unique<Key>(s, p, t);
}

auto ecdhGen(symmetric_cipher s, const Key &me, const Key &peer)
    -> std::unique_ptr<Key> {
  return std::make_unique<Key>(s, me, peer);
}

struct DecryptResult {
  Plaintext plaintext;
  bool needsVerify;
};

struct DeserializeResult {
  uintptr_t ciphertext;
  crypto_config_t config;
};

} // namespace js
} // namespace peacemakr

using namespace peacemakr;

EMSCRIPTEN_BINDINGS(peacemakr_core_crypto_web) {
  em::class_<RandomDevice>("RandomDevice")
      // Only allow the default constructor for now
      .constructor<>();

  em::enum_<symmetric_cipher>("SymmetricCipher")
      .value("UNSPECIFIED", symmetric_cipher::SYMMETRIC_UNSPECIFIED)
      .value("AES_128_GCM", symmetric_cipher::AES_128_GCM)
      .value("AES_192_GCM", symmetric_cipher::AES_192_GCM)
      .value("AES_256_GCM", symmetric_cipher::AES_256_GCM)
      .value("CHACHA20_POLY1305", symmetric_cipher::CHACHA20_POLY1305);

  em::enum_<asymmetric_cipher>("AsymmetricCipher")
      .value("UNSPECIFIED", asymmetric_cipher::ASYMMETRIC_UNSPECIFIED)
      .value("RSA_2048", asymmetric_cipher::RSA_2048)
      .value("RSA_4096", asymmetric_cipher::RSA_4096)
      .value("ECDH_P256", asymmetric_cipher::ECDH_P256)
      .value("ECDH_P384", asymmetric_cipher::ECDH_P384)
      .value("ECDH_P521", asymmetric_cipher::ECDH_P521);

  em::enum_<message_digest_algorithm>("DigestAlgorithm")
      .value("UNSPECIFIED", message_digest_algorithm::DIGEST_UNSPECIFIED)
      .value("SHA_224", message_digest_algorithm::SHA_224)
      .value("SHA_256", message_digest_algorithm::SHA_256)
      .value("SHA_384", message_digest_algorithm::SHA_384)
      .value("SHA_512", message_digest_algorithm::SHA_512);

  em::enum_<encryption_mode>("EncryptionMode")
      .value("SYMMETRIC", encryption_mode::SYMMETRIC)
      .value("ASYMMETRIC", encryption_mode::ASYMMETRIC);

  em::class_<crypto_config_t>("CryptoConfig")
      .property("mode", &crypto_config_t::mode)
      .property("symm_cipher", &crypto_config_t::symm_cipher)
      .property("asymm_cipher", &crypto_config_t::asymm_cipher)
      .property("digest_algorithm", &crypto_config_t::digest_algorithm);

  em::class_<Key>("Key")
      // Asymmetric key
      .class_function<std::unique_ptr<Key>, asymmetric_cipher, symmetric_cipher,
                      RandomDevice &>("new_asymmetric", &js::newAsymm)
      // Symmetric key
      .class_function<std::unique_ptr<Key>, symmetric_cipher, RandomDevice &>(
          "new_symmetric", &js::newSymm)
      // From bytes
      .class_function<std::unique_ptr<Key>, symmetric_cipher,
                      const std::string &>("from_bytes", &js::fromBytes)
      // From pem
      .class_function<std::unique_ptr<Key>, symmetric_cipher,
                      const std::string &, const std::string &>("from_pem",
                                                                &js::fromPem)
      // ECDH keygen
      .class_function<std::unique_ptr<Key>, symmetric_cipher, const Key &,
                      const Key &>("ecdh_keygen", &js::ecdhGen)

      // Methods available for calling
      .function("get_config", &Key::getConfig)
      .function("is_valid", &Key::isValid)
      .function("get_priv_pem", &Key::getPrivPem)
      .function("get_pub_pem", &Key::getPubPem)
      .function("get_bytes", &Key::getBytes);

  em::value_object<Plaintext>("Plaintext")
      .field("data", &Plaintext::data)
      .field("aad", &Plaintext::aad);

  em::value_object<js::DecryptResult>("DecryptResult")
      .field("plaintext", &js::DecryptResult::plaintext)
      .field("needs_verify", &js::DecryptResult::needsVerify);

  em::value_object<js::DeserializeResult>("DeserializeResult")
      .field("ciphertext", &js::DeserializeResult::ciphertext)
      .field("config", &js::DeserializeResult::config);

  em::class_<CryptoContext>("CryptoContext")
      .class_function("init", &js::ctxFactory)
      .function(
          "encrypt",
          std::function<uintptr_t(CryptoContext, const Key &, const Plaintext &,
                                  RandomDevice &)>(
              [](CryptoContext ctx, const Key &key, const Plaintext &plaintext,
                 RandomDevice &rand) -> uintptr_t {
                return (uintptr_t)ctx.Encrypt(key, plaintext, rand);
              }))
      .function("get_plaintext_blob",
                std::function<uintptr_t(CryptoContext, const Plaintext &)>(
                    [](CryptoContext ctx, const Plaintext &p) -> uintptr_t {
                      return (uintptr_t)ctx.GetPlaintextBlob(p);
                    }))
      .function("extract_plaintext_blob",
                std::function<Plaintext(CryptoContext, uintptr_t)>(
                    [](CryptoContext ctx, uintptr_t c) {
                      return ctx.ExtractPlaintextBlob(
                          reinterpret_cast<Ciphertext>(c));
                    }))
      .function(
          "sign",
          std::function<bool(CryptoContext, const Key &, const Plaintext &,
                             message_digest_algorithm, uintptr_t)>(
              [](CryptoContext ctx, const Key &senderKey,
                 const Plaintext &plaintext, message_digest_algorithm digest,
                 uintptr_t blob) -> bool {
                return ctx.Sign(senderKey, plaintext, digest,
                                reinterpret_cast<Ciphertext>(blob));
              }))
      .function("serialize",
                std::function<std::string(CryptoContext,
                                          message_digest_algorithm, uintptr_t)>(
                    [](CryptoContext ctx, message_digest_algorithm digest,
                       uintptr_t blob) {
                      return ctx.Serialize(digest,
                                           reinterpret_cast<Ciphertext>(blob));
                    }))
      .function("extract_unverified_aad", &CryptoContext::ExtractUnverifiedAAD)
      .function("deserialize",
                std::function<js::DeserializeResult(CryptoContext,
                                                    const std::string &)>(
                    [](CryptoContext ctx, const std::string &serialized)
                        -> js::DeserializeResult {
                      auto deser = ctx.Deserialize(serialized);
                      return js::DeserializeResult{.ciphertext =
                                                       (uintptr_t)deser.first,
                                                   .config = deser.second};
                    }))
      .function("decrypt",
                std::function<js::DecryptResult(CryptoContext, const Key &,
                                                uintptr_t)>(
                    [](CryptoContext ctx, const Key &key, uintptr_t blob) {
                      auto decr =
                          ctx.Decrypt(key, reinterpret_cast<Ciphertext>(blob));
                      return js::DecryptResult{.plaintext = decr.first,
                                               .needsVerify = decr.second};
                    }))
      .function("verify",
                std::function<bool(CryptoContext, const Key &,
                                   const Plaintext &, uintptr_t)>(
                    [](CryptoContext ctx, const Key &senderKey,
                       const Plaintext &plain, uintptr_t blob) {
                      return ctx.Verify(senderKey, plain,
                                        reinterpret_cast<Ciphertext>(blob));
                    }));
}
