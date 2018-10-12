//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <peacemakr/crypto.hpp>
#include <cassert>
#include <thread>
#include <algorithm>
#include <random>

void test_asymmetric(const std::string &msg, symmetric_cipher symm_cipher, asymmetric_cipher cipher, message_digest_algorithm digest) {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .symm_cipher = symm_cipher,
          .asymm_cipher = cipher,
          .digest_algorithm = digest
  };

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = msg;
  plaintext_in.aad = std::string(msg.rbegin(), msg.rend());

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(cfg, rand);

  peacemakr::CryptoContext ctx;
  std::string encrypted = ctx.Encrypt(key, plaintext_in, rand);
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, encrypted);

  assert(plaintext_in.data == plaintext_out.data);
  assert(plaintext_in.aad == plaintext_out.aad);
}

void test_symmetric(const std::string &msg, symmetric_cipher symm_cipher, message_digest_algorithm digest) {
  crypto_config_t cfg = {
          .mode = SYMMETRIC,
          .symm_cipher = symm_cipher,
          .asymm_cipher = NONE,
          .digest_algorithm = digest
  };

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = msg;
  plaintext_in.aad = std::string(msg.rbegin(), msg.rend());

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(cfg, rand);

  peacemakr::CryptoContext ctx;
  std::string encrypted = ctx.Encrypt(key, plaintext_in, rand);
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, encrypted);

  assert(plaintext_in.data == plaintext_out.data);
  assert(plaintext_in.aad == plaintext_out.aad);
}

int run(const uint8_t *data, size_t size) {
  std::vector<std::thread> runners;
  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      for (int k = SHA_224; k <= SHA_512; k++) {
        runners.emplace_back(test_asymmetric, std::string(data, data+size), (symmetric_cipher)j, (asymmetric_cipher)i, (message_digest_algorithm)k);
      }
    }
  }

  for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
    for (int k = SHA_224; k <= SHA_512; k++) {
      runners.emplace_back(test_symmetric, std::string(data, data+size), (symmetric_cipher)j, (message_digest_algorithm)k);
    }
  }

  std::for_each(runners.begin(), runners.end(), [](std::thread &t){t.join();});

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  return run(Data, Size);
}
