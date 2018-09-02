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

std::string get_random_string() {

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, (2<<7) - 1); // 0-127 (so it checks if we handle nulls as well)
  auto call = [&]() -> char {
    return (char)dis(gen);
  };

  size_t len = 10000;

  std::string out(len, '0');
  std::generate_n(out.begin(), len, call);

  return out;
}

void test_asymmetric(symmetric_cipher symm_cipher, asymmetric_cipher cipher, message_digest_algorithm digest) {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .symm_cipher = symm_cipher,
          .asymm_cipher = cipher,
          .digest_algorithm = digest
  };

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = get_random_string();
  plaintext_in.aad = get_random_string();

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(cfg, rand);

  peacemakr::CryptoContext ctx;
  std::string encrypted = ctx.Encrypt(key, plaintext_in, rand);
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, encrypted);

  assert(plaintext_in.data == plaintext_out.data);
  assert(plaintext_in.aad == plaintext_out.aad);
}

void test_symmetric(symmetric_cipher symm_cipher, message_digest_algorithm digest) {
  crypto_config_t cfg = {
          .mode = SYMMETRIC,
          .symm_cipher = symm_cipher,
          .asymm_cipher = NONE,
          .digest_algorithm = digest
  };

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = get_random_string();
  plaintext_in.aad = get_random_string();

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(cfg, rand);

  peacemakr::CryptoContext ctx;
  std::string encrypted = ctx.Encrypt(key, plaintext_in, rand);
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, encrypted);

  assert(plaintext_in.data == plaintext_out.data);
  assert(plaintext_in.aad == plaintext_out.aad);
}

int main() {
  std::vector<std::thread> runners;
  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      for (int k = SHA_224; k <= SHA_512; k++) {
        runners.emplace_back(test_asymmetric, (symmetric_cipher)j, (asymmetric_cipher)i, (message_digest_algorithm)k);
      }
    }
  }

  for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
    for (int k = SHA_224; k <= SHA_512; k++) {
      runners.emplace_back(test_symmetric, (symmetric_cipher)j, (message_digest_algorithm)k);
    }
  }

  std::for_each(runners.begin(), runners.end(), [](std::thread &t){t.join();});
}
