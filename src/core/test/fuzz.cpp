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
extern "C" {
  #include "../src/EVPHelper.h"
}

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

void test_symm_keygen(const uint8_t *data, size_t size, symmetric_cipher symm_cipher, message_digest_algorithm digest) {
  const EVP_CIPHER *symm_evp_cipher = parse_cipher(symm_cipher);
  size_t keylen = EVP_CIPHER_key_length(symm_evp_cipher);

  if (size < keylen) { // early exit if it's not big enough
    return;
  }

  crypto_config_t cfg = {
          .mode = SYMMETRIC,
          .symm_cipher = AES_128_GCM,
          .asymm_cipher = NONE,
          .digest_algorithm = SHA_256
  };

//  std::cout << symm_cipher << " " << digest << std::endl;

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = "Hello world!";
  plaintext_in.aad = "";

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(cfg, std::vector<uint8_t>(data, data+size));

  assert(key.isValid() || size >= keylen);

  peacemakr::CryptoContext ctx;
  std::string encrypted = ctx.Encrypt(key, plaintext_in, rand);
  if (encrypted.empty()) { // couldn't encrypt
    return;
  }

  // somehow there's a certain key that causes a crash in Decrypt?
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, encrypted);
  if (plaintext_out.data.empty()) {
    return;
  }

  assert(plaintext_in.data == plaintext_out.data && "symmetric encrypt-decrypt failed");
  assert(plaintext_in.aad == plaintext_out.aad && "symmetric encrypt-decrypt failed");
}

void test_asymm_keygen(const uint8_t *data, size_t size, symmetric_cipher symm_cipher, asymmetric_cipher cipher, message_digest_algorithm digest) {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .symm_cipher = symm_cipher,
          .asymm_cipher = cipher,
          .digest_algorithm = digest
  };

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = "Hello world!";
  plaintext_in.aad = "";

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key priv_key(cfg, std::string(data, data+size), true);
  assert(!priv_key.isValid() && "randomly generated a valid key?");

  peacemakr::Key pub_key(cfg, std::string(data, data+size), false);
  assert(!pub_key.isValid() && "randomly generated a valid key?");

//  peacemakr::CryptoContext ctx;
//  std::string encrypted = ctx.Encrypt(pub_key, plaintext_in, rand);
//  if (encrypted.empty()) { // couldn't encrypt
//    return;
//  }
//
//  peacemakr::Plaintext plaintext_out = ctx.Decrypt(priv_key, encrypted);
//
//  assert(plaintext_in.data == plaintext_out.data);
//  assert(plaintext_in.aad == plaintext_out.aad);
}

// Interesting problems exposed in keygen with fuzzing
int run(const uint8_t *data, size_t size) {
  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      for (int k = SHA_224; k <= SHA_512; k++) {
        test_asymmetric(std::string(data, data+size), (symmetric_cipher)j, (asymmetric_cipher)i, (message_digest_algorithm)k);
        test_asymm_keygen(data, size, (symmetric_cipher)j, (asymmetric_cipher)i, (message_digest_algorithm)k);
      }
    }
  }

  for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
    for (int k = SHA_224; k <= SHA_512; k++) {
      test_symmetric(std::string(data, data+size), (symmetric_cipher)j, (message_digest_algorithm)k);
      test_symm_keygen(data, size, (symmetric_cipher)AES_128_GCM, (message_digest_algorithm)SHA_256);
    }
  }

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  test_symm_keygen(Data, Size, (symmetric_cipher)AES_128_GCM, (message_digest_algorithm)SHA_256);
  return 0;
}
