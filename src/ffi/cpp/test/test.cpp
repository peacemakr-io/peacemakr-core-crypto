//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <algorithm>
#include <cassert>
#include <iostream>
#include <peacemakr/crypto.hpp>
#include <random>
#include <thread>

void log_fn(const std::string &str) { std::cerr << str << std::endl; }

std::string get_random_string() {

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dis(
      0, (2 << 7) - 1); // 0-127 (so it checks if we handle nulls as well)
  auto call = [&]() -> char { return (char)dis(gen); };

  size_t len = dis(gen) * 10; // also include zero-length randomly

  bool outIsEmpty = (dis(gen) % 2 == 1);
  if (outIsEmpty) {
    return std::string{};
  }

  std::string out(len, (char)0x0); // fill us up with null characters
  std::generate_n(out.begin(), len, call);

  return out;
}

void test_asymmetric(symmetric_cipher symm_cipher, asymmetric_cipher cipher,
                     message_digest_algorithm digest) {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = get_random_string();
  plaintext_in.aad = get_random_string();

  peacemakr::RandomDevice rand;

  peacemakr::Key key(cipher, symm_cipher, rand);

  peacemakr::CryptoContext ctx(log_fn);
  peacemakr::Ciphertext encrypted = ctx.Encrypt(key, plaintext_in, rand);
  if (encrypted == nullptr && plaintext_in.data.empty()) {
    return;
  } else {
    assert(encrypted != nullptr);
  }

  std::string serialized = ctx.Serialize(digest, encrypted);
  assert(!serialized.empty());

  if (!plaintext_in.aad.empty()) {
    peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(serialized);
    assert(plaintext_in.aad == unverified_aad.aad);
  }

  std::pair<peacemakr::Ciphertext, crypto_config_t> deserialized =
      ctx.Deserialize(serialized);
  std::pair<peacemakr::Plaintext, bool> plaintext_out =
      ctx.Decrypt(key, deserialized.first);
  assert(!plaintext_out.second);

  assert(plaintext_in.data == plaintext_out.first.data);
  assert(plaintext_in.aad == plaintext_out.first.aad);
}

void test_symmetric(symmetric_cipher symm_cipher,
                    message_digest_algorithm digest) {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = get_random_string();
  plaintext_in.aad = get_random_string();

  peacemakr::RandomDevice rand;

  peacemakr::Key key(symm_cipher, rand);

  peacemakr::CryptoContext ctx(log_fn);
  peacemakr::Ciphertext encrypted = ctx.Encrypt(key, plaintext_in, rand);
  if (encrypted == nullptr && plaintext_in.data.empty()) {
    return;
  } else {
    assert(encrypted != nullptr);
  }

  std::string serialized = ctx.Serialize(digest, encrypted);
  assert(!serialized.empty());

  if (!plaintext_in.aad.empty()) {
    peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(serialized);
    assert(plaintext_in.aad == unverified_aad.aad);
  }

  std::pair<peacemakr::Ciphertext, crypto_config_t> deserialized =
      ctx.Deserialize(serialized);
  std::pair<peacemakr::Plaintext, bool> plaintext_out =
      ctx.Decrypt(key, deserialized.first);
  assert(!plaintext_out.second);

  assert(plaintext_in.data == plaintext_out.first.data);
  assert(plaintext_in.aad == plaintext_out.first.aad);
}

void test_sign_symmetric(symmetric_cipher symm_cipher,
                         message_digest_algorithm digest) {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = get_random_string();
  plaintext_in.aad = get_random_string();

  peacemakr::RandomDevice rand;

  peacemakr::Key key(symm_cipher, rand);

  peacemakr::CryptoContext ctx(log_fn);
  peacemakr::Ciphertext encrypted = ctx.Encrypt(key, plaintext_in, rand);
  if (encrypted == nullptr && plaintext_in.data.empty()) {
    return;
  } else {
    assert(encrypted != nullptr);
  }
  assert(ctx.Sign(key, plaintext_in, digest, encrypted));

  std::string serialized = ctx.Serialize(digest, encrypted);
  assert(!serialized.empty());

  if (!plaintext_in.aad.empty()) {
    peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(serialized);
    assert(plaintext_in.aad == unverified_aad.aad);
  }

  std::pair<peacemakr::Ciphertext, crypto_config_t> deserialized =
      ctx.Deserialize(serialized);
  std::pair<peacemakr::Plaintext, bool> plaintext_out =
      ctx.Decrypt(key, deserialized.first);
  assert(plaintext_out.second);
  bool verified = ctx.Verify(key, plaintext_out.first, deserialized.first);
  assert(verified);

  assert(plaintext_in.data == plaintext_out.first.data);
  assert(plaintext_in.aad == plaintext_out.first.aad);
}

void test_sign_asymmetric(symmetric_cipher symm_cipher,
                          asymmetric_cipher cipher,
                          message_digest_algorithm digest) {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = get_random_string();
  plaintext_in.aad = get_random_string();

  peacemakr::RandomDevice rand;

  peacemakr::Key key(cipher, symm_cipher, rand);

  peacemakr::CryptoContext ctx(log_fn);
  peacemakr::Ciphertext encrypted = ctx.Encrypt(key, plaintext_in, rand);
  if (encrypted == nullptr && plaintext_in.data.empty()) {
    return;
  } else {
    assert(encrypted != nullptr);
  }
  assert(ctx.Sign(key, plaintext_in, digest, encrypted));

  std::string serialized = ctx.Serialize(digest, encrypted);
  assert(!serialized.empty());

  if (!plaintext_in.aad.empty()) {
    peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(serialized);
    assert(plaintext_in.aad == unverified_aad.aad);
  }

  std::pair<peacemakr::Ciphertext, crypto_config_t> deserialized =
      ctx.Deserialize(serialized);
  std::pair<peacemakr::Plaintext, bool> plaintext_out =
      ctx.Decrypt(key, deserialized.first);
  assert(plaintext_out.second);
  bool verified = ctx.Verify(key, plaintext_out.first, deserialized.first);
  assert(verified);

  if (!plaintext_in.data.empty()) {
    assert(plaintext_in.data == plaintext_out.first.data);
  }
  if (!plaintext_in.aad.empty()) {
    assert(plaintext_in.aad == plaintext_out.first.aad);
  }
}

void test_uninit_crash() {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = "Hello world!";
  plaintext_in.aad = "";

  peacemakr::RandomDevice rand;

  peacemakr::Key key(AES_128_GCM, rand);
  assert(key.isValid());

  peacemakr::CryptoContext ctx(log_fn);
  peacemakr::Ciphertext encrypted = ctx.Encrypt(key, plaintext_in, rand);
  if (encrypted == nullptr && plaintext_in.data.empty()) {
    return;
  } else {
    assert(encrypted != nullptr);
  }

  std::string serialized = ctx.Serialize(SHA_256, encrypted);
  assert(!serialized.empty());

  if (!plaintext_in.aad.empty()) {
    peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(serialized);
    assert(plaintext_in.aad == unverified_aad.aad);
  }

  std::pair<peacemakr::Ciphertext, crypto_config_t> deserialized =
      ctx.Deserialize(serialized);
  std::pair<peacemakr::Plaintext, bool> plaintext_out =
      ctx.Decrypt(key, deserialized.first);
  assert(!plaintext_out.second);
  if (plaintext_out.first.data.empty()) { // couldn't decrypt
    assert(false);
  }

  assert(plaintext_in.data == plaintext_out.first.data &&
         "symmetric encrypt-decrypt failed");
  assert(plaintext_in.aad == plaintext_out.first.aad &&
         "symmetric encrypt-decrypt failed");
}

void test_sign_only() {
  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = "Hello world!";
  plaintext_in.aad = "AAD";

  peacemakr::RandomDevice rand;

  peacemakr::Key key(RSA_2048, AES_128_GCM, rand);
  assert(key.isValid());

  peacemakr::CryptoContext ctx(log_fn);
  peacemakr::Ciphertext encrypted = ctx.GetPlaintextBlob(plaintext_in);
  if (encrypted == nullptr && plaintext_in.data.empty()) {
    return;
  } else {
    assert(encrypted != nullptr);
  }

  bool didSign = ctx.Sign(key, plaintext_in, SHA_256, encrypted);
  assert(didSign);

  std::string serialized = ctx.Serialize(SHA_256, encrypted);
  assert(!serialized.empty());

  std::pair<peacemakr::Ciphertext, crypto_config_t> deserialized =
      ctx.Deserialize(serialized);

  peacemakr::Plaintext extracted = ctx.ExtractPlaintextBlob(deserialized.first);

  bool verif = ctx.Verify(key, extracted, deserialized.first);
  assert(verif);

  assert(plaintext_in.data == extracted.data &&
         "asymmetric sign-verify failed");
  assert(plaintext_in.aad == extracted.aad &&
         "asymmetric sign-verify failed");
}

void test_dh_symmetric(symmetric_cipher symm_cipher,
                       message_digest_algorithm digest) {

  peacemakr::Plaintext plaintext_in;
  plaintext_in.data = get_random_string();
  plaintext_in.aad = get_random_string();

  peacemakr::RandomDevice rand;

  peacemakr::Key myKey(ECDH_P256, SYMMETRIC_UNSPECIFIED, rand);
  peacemakr::Key peerKey(ECDH_P256, SYMMETRIC_UNSPECIFIED, rand);

  peacemakr::Key sharedKey(symm_cipher, myKey, peerKey);

  peacemakr::CryptoContext ctx(log_fn);
  peacemakr::Ciphertext encrypted = ctx.Encrypt(sharedKey, plaintext_in, rand);
  if (encrypted == nullptr && plaintext_in.data.empty()) {
    return;
  } else {
    assert(encrypted != nullptr);
  }
  assert(ctx.Sign(sharedKey, plaintext_in, digest, encrypted));

  std::string serialized = ctx.Serialize(digest, encrypted);
  assert(!serialized.empty());

  if (!plaintext_in.aad.empty()) {
    peacemakr::Plaintext unverified_aad = ctx.ExtractUnverifiedAAD(serialized);
    assert(plaintext_in.aad == unverified_aad.aad);
  }

  std::pair<peacemakr::Ciphertext, crypto_config_t> deserialized =
      ctx.Deserialize(serialized);
  std::pair<peacemakr::Plaintext, bool> plaintext_out =
      ctx.Decrypt(sharedKey, deserialized.first);
  assert(plaintext_out.second);
  bool verified =
      ctx.Verify(sharedKey, plaintext_out.first, deserialized.first);
  assert(verified);

  assert(plaintext_in.data == plaintext_out.first.data);
  assert(plaintext_in.aad == plaintext_out.first.aad);
}

int main() {
  std::vector<std::thread> runners;
  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      for (int k = SHA_224; k <= SHA_512; k++) {
        runners.emplace_back(test_asymmetric, (symmetric_cipher)j,
                             (asymmetric_cipher)i, (message_digest_algorithm)k);
        runners.emplace_back(test_sign_asymmetric, (symmetric_cipher)j,
                             (asymmetric_cipher)i, (message_digest_algorithm)k);
      }
      std::for_each(runners.begin(), runners.end(),
                    [](std::thread &t) { t.join(); });
      runners.clear();
    }
  }

  for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
    for (int k = SHA_224; k <= SHA_512; k++) {
      runners.emplace_back(test_symmetric, (symmetric_cipher)j,
                           (message_digest_algorithm)k);
      runners.emplace_back(test_sign_symmetric, (symmetric_cipher)j,
                           (message_digest_algorithm)k);
      runners.emplace_back(test_dh_symmetric, (symmetric_cipher)j,
                           (message_digest_algorithm)k);
    }
  }

  std::for_each(runners.begin(), runners.end(),
                [](std::thread &t) { t.join(); });

  test_uninit_crash();
  test_sign_only();
}
