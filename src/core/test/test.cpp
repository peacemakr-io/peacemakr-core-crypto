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
#include <iostream>

void log_fn(const std::string &str) {
  std::cerr << str << std::endl;
}

std::string get_random_string() {

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dis(0, (2<<7) - 1); // 0-127 (so it checks if we handle nulls as well)
  auto call = [&]() -> char {
    return (char)dis(gen);
  };

  size_t len = dis(gen) * 10; // also include zero-length randomly

  std::string out(len, (char)0x0); // fill us up with null characters
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

  peacemakr::CryptoContext ctx(log_fn);
  std::string encrypted = ctx.Encrypt(&key, &key, plaintext_in, rand);

  peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(encrypted);
  assert(plaintext_in.aad == unverified_aad.aad);

  peacemakr::Plaintext plaintext_out = ctx.Decrypt(&key, &key, encrypted);

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

  peacemakr::CryptoContext ctx(log_fn);
  std::string encrypted = ctx.Encrypt(&key, nullptr, plaintext_in, rand);

  peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(encrypted);
  assert(plaintext_in.aad == unverified_aad.aad);

  peacemakr::Plaintext plaintext_out = ctx.Decrypt(&key, nullptr, encrypted);

  assert(plaintext_in.data == plaintext_out.data);
  assert(plaintext_in.aad == plaintext_out.aad);
}

void test_uninit_crash() {
  crypto_config_t cfg = {
          .mode = SYMMETRIC,
          .symm_cipher = AES_128_GCM,
          .asymm_cipher = NONE,
          .digest_algorithm = SHA_256
  };

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = "Hello world!";
  plaintext_in.aad = "";

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(cfg, rand);
  assert(key.isValid());

  peacemakr::CryptoContext ctx(log_fn);
  std::string encrypted = ctx.Encrypt(&key, nullptr, plaintext_in, rand);
  if (encrypted.empty()) { // couldn't encrypt
    assert(false);
  }

  peacemakr::Plaintext plaintext_out = ctx.Decrypt(&key, nullptr, encrypted);
  if (plaintext_out.data.empty()) { // couldn't decrypt
    assert(false);
  }

  assert(plaintext_in.data == plaintext_out.data && "symmetric encrypt-decrypt failed");
  assert(plaintext_in.aad == plaintext_out.aad && "symmetric encrypt-decrypt failed");
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

  std::for_each(runners.begin(), runners.end(), [](std::thread &t){t.join();});
  runners.clear();

  for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
    for (int k = SHA_224; k <= SHA_512; k++) {
      runners.emplace_back(test_symmetric, (symmetric_cipher)j, (message_digest_algorithm)k);
    }
  }

  std::for_each(runners.begin(), runners.end(), [](std::thread &t){t.join();});

  test_uninit_crash();
}
