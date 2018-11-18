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

const char *message = "Hello, world! I'm testing encryption from C!"; // 37 + 1
const char *message_aad = "And I'm AAD"; // 11 + 1

void test_serialize(symmetric_cipher symm_cipher, asymmetric_cipher cipher, message_digest_algorithm digest) {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .symm_cipher = symm_cipher,
          .asymm_cipher = cipher,
          .digest_algorithm = digest
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
  assert(ciphertext != NULL);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(ciphertext, &out_size);
  assert(serialized != NULL);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized = peacemakr_deserialize(serialized, out_size, &out_cfg);
  decrypt_code success = peacemakr_decrypt(key, deserialized, &plaintext_out);

  assert((out_cfg.mode == cfg.mode) &&
         (out_cfg.asymm_cipher == cfg.asymm_cipher) &&
         (out_cfg.symm_cipher == cfg.symm_cipher) &&
         (out_cfg.digest_algorithm == cfg.digest_algorithm));

  assert(success == DECRYPT_SUCCESS);
  free(serialized);

  assert(strncmp((const char *)plaintext_out.data, (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad, (const char *)plaintext_in.aad, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(key);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      for (int k = SHA_224; k <= SHA3_512; k++) {
        test_serialize(j, i, k);
      }
    }
  }
}


