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

const char *message = "Hello, world! I'm testing encryption."; // 37 + 1
const char *message_aad = "And I'm AAD"; // 11 + 1

int main() {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .asymm_cipher = RSA_2048, // ec25519 causes problems
          .symm_cipher = AES_256_CTR,
          .digest_algorithm = SHA_512
  };

  plaintext_t plaintext_in = {
          .data = message,
          .data_len = strlen(message) + 1,
          .aad = message_aad,
          .aad_len = strlen(message_aad) + 1
  };

  plaintext_t plaintext_out;

  random_device_t rand = {
          .generator = &fill_rand,
          .err = &rand_err
  };

  peacemakr_key_t *key = PeacemakrKey_new(cfg, rand);

  ciphertext_blob_t *ciphertext = encrypt(cfg, &key, 1, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  bool success = decrypt(key, ciphertext, &plaintext_out);

  assert(success);

  assert(strncmp(plaintext_out.data, plaintext_in.data, plaintext_in.data_len) == 0);
  assert(strncmp(plaintext_out.aad, plaintext_in.aad, plaintext_in.data_len) == 0);

}

