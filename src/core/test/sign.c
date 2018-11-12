//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <peacemakr/crypto.h>
#include <peacemakr/random.h>
#include <memory.h>
#include <assert.h>

#include "test_helper.h"
#include "../src/CiphertextBlob.h"

const char *message = "Hello, world! I'm testing encryption."; // 37 + 1
const char *message_aad = "And I'm AAD"; // 11 + 1

void test_symmetric_algo(symmetric_cipher cipher) {
  crypto_config_t cfg = {
          .mode = SYMMETRIC,
          .symm_cipher = cipher,
          .digest_algorithm = SHA_512
  };

  plaintext_t plaintext_in = {
          .data = (const unsigned char *)message,
          .data_len = strlen(message) + 1,
          .aad = (const unsigned char *)message_aad,
          .aad_len = strlen(message_aad) + 1
  };

  plaintext_t plaintext_out;

  random_device_t rand = {
          .generator = &fill_rand,
          .err = &rand_err
  };

  peacemakr_key_t *key = PeacemakrKey_new(cfg, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  peacemakr_sign(key, &plaintext_in, ciphertext);
  assert(ciphertext != NULL);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(ciphertext, &out_size);
  assert(serialized != NULL);

  ciphertext_blob_t *deserialized = peacemakr_deserialize(serialized, out_size);
  bool success = peacemakr_decrypt(key, deserialized, &plaintext_out);
  success &= peacemakr_verify(key, &plaintext_out, deserialized);

  assert(success);

  assert(strncmp((const char *)plaintext_out.data, (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad, (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(key);
}

void test_asymmetric_algo(symmetric_cipher cipher, asymmetric_cipher asymmcipher) {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .symm_cipher = cipher,
          .asymm_cipher = asymmcipher,
          .digest_algorithm = SHA_512
  };

  plaintext_t plaintext_in = {
          .data = (const unsigned char *)message,
          .data_len = strlen(message) + 1,
          .aad = (const unsigned char *)message_aad,
          .aad_len = strlen(message_aad) + 1
  };

  plaintext_t plaintext_out;

  random_device_t rand = {
          .generator = &fill_rand,
          .err = &rand_err
  };

  peacemakr_key_t *key = PeacemakrKey_new(cfg, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  peacemakr_sign(key, &plaintext_in, ciphertext);
  assert(ciphertext != NULL);

  size_t out_size = 0;
  // this isn't serializing the signature properly...
  uint8_t *serialized = peacemakr_serialize(ciphertext, &out_size);
  assert(serialized != NULL);

  // or this isn't deserializing the signature properly...
  ciphertext_blob_t *deserialized = peacemakr_deserialize(serialized, out_size);
  decrypt_code success = peacemakr_decrypt(key, deserialized, &plaintext_out);
  assert(success == DECRYPT_NEED_VERIFY);
  assert(peacemakr_verify(key, &plaintext_out, deserialized));

  assert(strncmp((const char *)plaintext_out.data, (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad, (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(key);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
    test_symmetric_algo(i);
  }

  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      test_asymmetric_algo(j, i);
    }
  }
}
