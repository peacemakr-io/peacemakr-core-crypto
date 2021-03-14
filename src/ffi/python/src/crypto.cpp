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
#include <pybind11/pybind11.h>

namespace py = pybind11;

namespace peacemakr {
namespace python {

void logFn(const std::string &s) {
  py::object logModule = py::module::import("logging");
  py::object warnLog = logModule.attr("warning");
  warnLog(s);
}

} // namespace python
} // namespace peacemakr

using namespace peacemakr;

PYBIND11_MODULE(peacemakr_core_crypto_python, m) {
  py::class_<RandomDevice>(m, "RandomDevice")
      // Only allow the default initialzer for now
      .def(py::init<>());

  py::enum_<symmetric_cipher>(m, "SymmetricCipher")
      .value("UNSPECIFIED", symmetric_cipher::SYMMETRIC_UNSPECIFIED)
      .value("AES_128_GCM", symmetric_cipher::AES_128_GCM)
      .value("AES_192_GCM", symmetric_cipher::AES_192_GCM)
      .value("AES_256_GCM", symmetric_cipher::AES_256_GCM)
      .value("CHACHA20_POLY1305", symmetric_cipher::CHACHA20_POLY1305)
      .export_values();

  py::enum_<asymmetric_cipher>(m, "AsymmetricCipher")
      .value("UNSPECIFIED", asymmetric_cipher::ASYMMETRIC_UNSPECIFIED)
      .value("RSA_2048", asymmetric_cipher::RSA_2048)
      .value("RSA_4096", asymmetric_cipher::RSA_4096)
      .value("ECDH_P256", asymmetric_cipher::ECDH_P256)
      .value("ECDH_P384", asymmetric_cipher::ECDH_P384)
      .value("ECDH_P521", asymmetric_cipher::ECDH_P521)
      .export_values();

  py::enum_<message_digest_algorithm>(m, "DigestAlgorithm")
      .value("UNSPECIFIED", message_digest_algorithm::DIGEST_UNSPECIFIED)
      .value("SHA_224", message_digest_algorithm::SHA_224)
      .value("SHA_256", message_digest_algorithm::SHA_256)
      .value("SHA_384", message_digest_algorithm::SHA_384)
      .value("SHA_512", message_digest_algorithm::SHA_512)
      .export_values();

  py::enum_<encryption_mode>(m, "EncryptionMode")
      .value("SYMMETRIC", encryption_mode::SYMMETRIC)
      .value("ASYMMETRIC", encryption_mode::ASYMMETRIC)
      .export_values();

  py::class_<crypto_config_t>(m, "CryptoConfig")
      .def_readwrite("mode", &crypto_config_t::mode)
      .def_readwrite("symm_cipher", &crypto_config_t::symm_cipher)
      .def_readwrite("asymm_cipher", &crypto_config_t::asymm_cipher)
      .def_readwrite("digest_algorithm", &crypto_config_t::digest_algorithm);

  py::class_<Key>(m, "Key")
      // Asymmetric key
      .def(py::init<asymmetric_cipher, symmetric_cipher, RandomDevice &>())
      // Symmetric key
      .def(py::init<symmetric_cipher, RandomDevice &>())
      // From bytes/priv pem
      .def(py::init<symmetric_cipher, const std::string &>())
      // From password and salt
      .def(py::init<symmetric_cipher, message_digest_algorithm,
                    const std::string &, const std::string &, const size_t>())
      // From master
      .def(py::init<symmetric_cipher, message_digest_algorithm, const Key &,
                    const std::string &>())
      // From pub pem/cert (second arg is the trust store)
      .def(py::init<symmetric_cipher, const std::string &,
                    const std::string &>())
      // ECDH keygen
      .def(py::init<symmetric_cipher, const Key &, const Key &>())

      // Methods available for calling
      .def("get_config", &Key::getConfig)
      .def("is_valid", &Key::isValid)
      .def("get_csr", &Key::getCSR)
      .def("add_certificate", &Key::addCertificate)
      .def("get_priv_pem", &Key::getPrivPem)
      .def("get_pub_pem", &Key::getPubPem)
      .def("get_certificate", &Key::getCertificate)
      .def("get_bytes", [](const Key &k) { return py::bytes(k.getBytes()); });

  py::class_<Plaintext>(m, "Plaintext")
      .def(py::init([](const py::bytes &data,
                       const py::bytes &aad) -> std::unique_ptr<Plaintext> {
        auto p = std::make_unique<Plaintext>();
        p->data = data;
        p->aad = aad;

        return p;
      }))
      .def(py::init([](const std::string &data,
                       const std::string &aad) -> std::unique_ptr<Plaintext> {
        auto p = std::make_unique<Plaintext>();
        p->data = data;
        p->aad = aad;

        return p;
      }))
      .def(py::init([]() -> std::unique_ptr<Plaintext> {
        return std::make_unique<Plaintext>();
      }))
      .def_property(
          "data", [](const Plaintext &p) { return py::bytes(p.data); },
          [](Plaintext &p, py::bytes data) { p.data = std::move(data); })
      .def_property(
          "aad", [](const Plaintext &p) { return py::bytes(p.aad); },
          [](Plaintext &p, py::bytes aad) { p.aad = std::move(aad); });

  py::class_<CryptoContext>(m, "CryptoContext")
      .def(py::init(
          []() { return std::make_unique<CryptoContext>(&python::logFn); }))
      .def("encrypt", &CryptoContext::Encrypt)
      .def("sign", &CryptoContext::Sign)
      .def("serialize", &CryptoContext::Serialize)
      .def("decrypt", &CryptoContext::Decrypt)
      .def("verify", &CryptoContext::Verify)
      .def("deserialize", &CryptoContext::Deserialize)
      .def("get_plaintext_blob", &CryptoContext::GetPlaintextBlob)
      .def("extract_plaintext_blob", &CryptoContext::ExtractPlaintextBlob)
      .def("extract_unverified_aad", &CryptoContext::ExtractUnverifiedAAD);
}
