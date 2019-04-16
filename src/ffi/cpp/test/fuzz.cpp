//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <peacemakr/crypto.hpp>
#include <cassert>
#include <cstdlib>
#include <thread>
#include <algorithm>
#include <random>
#include <iostream>
extern "C" {
  #include "../../src/EVPHelper.h"
  #include "../../src/Logging.h"
  #include "test_helper.h"
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

  peacemakr::Key key(cipher, symm_cipher, rand);

  peacemakr::CryptoContext ctx;
  peacemakr::Ciphertext *ciphertext = ctx.Encrypt(key, plaintext_in, rand);
  bool need_verify = false;
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, ciphertext, need_verify);

  assert(plaintext_in.data == plaintext_out.data);
  assert(plaintext_in.aad == plaintext_out.aad);
}

void test_symmetric(const std::string &msg, symmetric_cipher symm_cipher, message_digest_algorithm digest) {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = msg;
  plaintext_in.aad = std::string(msg.rbegin(), msg.rend());

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(symm_cipher, rand);

  peacemakr::CryptoContext ctx;
  peacemakr::Ciphertext *ciphertext = ctx.Encrypt(key, plaintext_in, rand);
  bool need_verify = false;
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, ciphertext, need_verify);

  assert(plaintext_in.data == plaintext_out.data);
  assert(plaintext_in.aad == plaintext_out.aad);
}

void test_symm_keygen(const uint8_t *data, size_t size, symmetric_cipher symm_cipher, message_digest_algorithm digest) {
  const EVP_CIPHER *symm_evp_cipher = parse_cipher(symm_cipher);
  size_t keylen = EVP_CIPHER_key_length(symm_evp_cipher);

  if (size < keylen) { // early exit if it's not big enough
    return;
  }

//  std::cout << symm_cipher << " " << digest << std::endl;

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = "Hello world!";
  plaintext_in.aad = "";

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key key(AES_128_GCM, std::vector<uint8_t>(data, data+size));

  assert(key.isValid() || size >= keylen);

  peacemakr::CryptoContext ctx;
  peacemakr::Ciphertext *ciphertext = ctx.Encrypt(key, plaintext_in, rand);
  std::string encrypted = ctx.Serialize(digest, ciphertext);
  if (encrypted.empty()) { // couldn't encrypt
    return;
  }

  // somehow there's a certain key that causes a crash in Decrypt?
  bool need_verify = false;
  crypto_config_t out_cfg;
  peacemakr::Plaintext plaintext_out = ctx.Decrypt(key, ctx.Deserialize(encrypted, &out_cfg), need_verify);
  if (plaintext_out.data.empty()) {
    return;
  }

  assert(plaintext_in.data == plaintext_out.data && "symmetric encrypt-decrypt failed");
  assert(plaintext_in.aad == plaintext_out.aad && "symmetric encrypt-decrypt failed");
}

void test_asymm_keygen(const uint8_t *data, size_t size, symmetric_cipher symm_cipher, asymmetric_cipher cipher, message_digest_algorithm digest) {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = "Hello world!";
  plaintext_in.aad = "";

  peacemakr::RandomDevice rand = peacemakr::RandomDevice::getDefault();

  peacemakr::Key priv_key(cipher, symm_cipher, std::string(data, data+size), true);
  assert(!priv_key.isValid() && "randomly generated a valid key?");

  peacemakr::Key pub_key(cipher, symm_cipher, std::string(data, data+size), false);
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

void test_deserialize(const uint8_t *data, size_t size) {
  crypto_config_t out_cfg = {};
  uint8_t null_term_data[size + 1];
  null_term_data[size] = '\0';
  peacemakr_deserialize(null_term_data, size + 1, &out_cfg);
}

void test_encrypt(peacemakr_key_t *key, random_device_t *rand, const uint8_t *data, size_t size) {
  plaintext_t plain = {
          .data = data,
          .data_len = size,
          .aad = nullptr,
          .aad_len = 0,
  };

  plaintext_t out_pt = {};

  ciphertext_blob_t *out = peacemakr_encrypt(key, &plain, rand);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(SHA_256, out, &out_size);

  crypto_config_t out_cfg = {};
  ciphertext_blob_t *deserialized = peacemakr_deserialize(serialized, out_size, &out_cfg);
  peacemakr_decrypt(key, deserialized, &out_pt);

  assert(memcmp(data, out_pt.data, out_pt.data_len) == 0);
  // Free the decrypted data
  free((void *)out_pt.data);
  free((void *)serialized);
}

void test_log(const uint8_t *data, size_t size) {
  char str[size + 1];
  str[size] = '\0';
  memcpy(str, data, size);
  PEACEMAKR_ERROR("%s", str);
}

random_device_t global_rand = {.generator = &fill_rand, .err = &rand_err};
peacemakr_key_t *key = peacemakr_key_new_symmetric(AES_256_GCM, &global_rand);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
//  test_log(Data, Size);
  test_encrypt(key, &global_rand, Data, Size);
  test_deserialize(Data, Size);
  return 0;
}
