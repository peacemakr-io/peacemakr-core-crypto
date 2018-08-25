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
#include <printf.h>

#include "test_helper.h"

const char *message = "Hello, world! I'm testing encryption."; // 37 + 1
const char *message_aad = "And I'm AAD"; // 11 + 1

void test_asymmetric_algo(symmetric_cipher symm_cipher, asymmetric_cipher cipher) {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .asymm_cipher = cipher,
          .symm_cipher = symm_cipher,
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

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(cfg, key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  bool success = peacemakr_decrypt(key, ciphertext, &plaintext_out);

  assert(success);

  assert(strncmp((const char *)plaintext_out.data, (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  assert(strncmp((const char *)plaintext_out.aad, (const char *)plaintext_in.aad, plaintext_in.data_len) == 0);

  PeacemakrKey_free(key);
}

int main() {
  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      test_asymmetric_algo(j, i);
    }
  }
}

