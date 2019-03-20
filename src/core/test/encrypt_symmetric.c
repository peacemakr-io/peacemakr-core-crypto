//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <assert.h>
#include <memory.h>
#include <peacemakr/crypto.h>

#include "test_helper.h"

const char *message = "Hello, world! I'm testing encryption."; // 37 + 1
const char *message_aad = "And I'm AAD";                       // 11 + 1

void test_symmetric_algo(symmetric_cipher cipher) {
  crypto_config_t cfg = {
      .mode = SYMMETRIC, .symm_cipher = cipher, .digest_algorithm = SHA_512};

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *original_key = PeacemakrKey_new(cfg, &rand);

  uint8_t *key_bytes = NULL;
  size_t key_size = 0;
  PeacemakrKey_get_bytes(original_key, &key_bytes, &key_size);

  peacemakr_key_t *key = PeacemakrKey_new_bytes(cfg, key_bytes, key_size);
  free(key_bytes);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  decrypt_code success = peacemakr_decrypt(key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(original_key);
  PeacemakrKey_free(key);
}

void test_master_key_symmetric_algo(peacemakr_key_t *master_key,
                                    symmetric_cipher cipher) {
  crypto_config_t cfg = {
      .mode = SYMMETRIC, .symm_cipher = cipher, .digest_algorithm = SHA_512};

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *key = PeacemakrKey_new_from_master(
      cfg, master_key, (uint8_t *)"abcdefghijk", 11);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  decrypt_code success = peacemakr_decrypt(key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(key);
}

void test_uninit_crash() {
  crypto_config_t cfg = {.mode = SYMMETRIC,
                         .symm_cipher = AES_128_GCM,
                         .asymm_cipher = NONE,
                         .digest_algorithm = SHA_256};

  plaintext_t plaintext_in = {.data = (const unsigned char *)"Hello world!",
                              .data_len = 12 + 1,
                              .aad = NULL,
                              .aad_len = 0};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *key = PeacemakrKey_new(cfg, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(ciphertext, &out_size);
  assert(serialized != NULL);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(serialized, out_size, &out_cfg);

  free(serialized);

  decrypt_code success = peacemakr_decrypt(key, deserialized, &plaintext_out);

  assert((out_cfg.mode == cfg.mode) &&
         (out_cfg.asymm_cipher == cfg.asymm_cipher) &&
         (out_cfg.symm_cipher == cfg.symm_cipher) &&
         (out_cfg.digest_algorithm == cfg.digest_algorithm));

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  if (plaintext_in.aad != NULL) {
    assert(strncmp((const char *)plaintext_out.aad,
                   (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
    free((void *)plaintext_out.aad);
  }

  PeacemakrKey_free(key);
}

void test_wrong_key(symmetric_cipher cipher) {
  crypto_config_t cfg = {
      .mode = SYMMETRIC, .symm_cipher = cipher, .digest_algorithm = SHA_512};

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *original_key = PeacemakrKey_new(cfg, &rand);

  ciphertext_blob_t *ciphertext =
      peacemakr_encrypt(original_key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  uint8_t *key_bytes = NULL;
  size_t key_size = 0;
  PeacemakrKey_get_bytes(original_key, &key_bytes, &key_size);
  key_bytes[0] += 1;

  peacemakr_key_t *key = PeacemakrKey_new_bytes(cfg, key_bytes, key_size);
  free(key_bytes);

  decrypt_code success = peacemakr_decrypt(key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_FAILED);

  CiphertextBlob_free(ciphertext);
  PeacemakrKey_free(original_key);
  PeacemakrKey_free(key);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  test_uninit_crash();

  for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
    test_symmetric_algo(i);
    test_wrong_key(i);
  }

  crypto_config_t cfg = {.mode = SYMMETRIC,
                         .symm_cipher = AES_256_GCM,
                         .digest_algorithm = SHA_512};

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *master_key = PeacemakrKey_new(cfg, &rand);

  for (int i = AES_256_GCM; i <= CHACHA20_POLY1305; ++i) {
    test_master_key_symmetric_algo(master_key, i);
  }

  PeacemakrKey_free(master_key);
}
