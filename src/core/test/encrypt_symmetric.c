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

#include "utils/helper.h"

const char *message = "Hello, world! I'm testing encryption."; // 37 + 1
const char *message_aad = "And I'm AAD";                       // 11 + 1

void test_symmetric_algo(symmetric_cipher cipher) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *original_key = peacemakr_key_new_symmetric(cipher, &rand);

  uint8_t *key_bytes = NULL;
  size_t key_size = 0;
  assert(peacemakr_key_get_bytes(original_key, &key_bytes, &key_size));

  peacemakr_key_t *key = peacemakr_key_new_bytes(cipher, key_bytes, key_size);
  free(key_bytes);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  plaintext_t aad;
  assert(peacemakr_get_unverified_aad(ciphertext, &aad));
  assert(memcmp(aad.aad, plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)aad.aad);

  decrypt_code success = peacemakr_decrypt(key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(memcmp(plaintext_out.data, plaintext_in.data, plaintext_in.data_len) ==
         0);
  free((void *)plaintext_out.data);
  assert(memcmp(plaintext_out.aad, plaintext_in.aad, plaintext_in.aad_len) ==
         0);
  free((void *)plaintext_out.aad);

  peacemakr_key_free(original_key);
  peacemakr_key_free(key);
}

void test_password_symmetric_algo(symmetric_cipher cipher,
                                  message_digest_algorithm digest) {

  size_t num_iters = rand() % 50000;

  peacemakr_key_t *key =
      peacemakr_key_new_from_password(cipher, digest, (uint8_t *)"abcdefghijk",
                                      11, (uint8_t *)"123456789", 9, num_iters);

  peacemakr_key_t *key_dup =
      peacemakr_key_new_from_password(cipher, digest, (uint8_t *)"abcdefghijk",
                                      11, (uint8_t *)"123456789", 9, num_iters);

  peacemakr_key_t *key2 =
      peacemakr_key_new_from_password(cipher, digest, (uint8_t *)"abcdefghijl",
                                      11, (uint8_t *)"123456789", 9, num_iters);

  uint8_t *key_buf = NULL;
  size_t key_buf_len = 0;
  assert(peacemakr_key_get_bytes(key, &key_buf, &key_buf_len));

  uint8_t *key_dup_buf = NULL;
  size_t key_dup_buf_len = 0;
  assert(peacemakr_key_get_bytes(key_dup, &key_dup_buf, &key_dup_buf_len));

  uint8_t *key2_buf = NULL;
  size_t key2_buf_len = 0;
  assert(peacemakr_key_get_bytes(key2, &key2_buf, &key2_buf_len));

  assert(key_buf_len == key_dup_buf_len);
  assert(key_buf_len == key2_buf_len);
  assert(memcmp(key_buf, key_dup_buf, key_buf_len) == 0);
  assert(memcmp(key_buf, key2_buf, key_buf_len) != 0);

  peacemakr_key_free(key);
  free(key_buf);
  peacemakr_key_free(key_dup);
  free(key_dup_buf);
  peacemakr_key_free(key2);
  free(key2_buf);
}

void test_master_key_symmetric_algo(peacemakr_key_t *master_key,
                                    symmetric_cipher cipher,
                                    message_digest_algorithm digest) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *key = peacemakr_key_new_from_master(
      cipher, digest, master_key, (uint8_t *)"abcdefghijk", 11);

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

  peacemakr_key_free(key);
}

void test_uninit_crash() {
  crypto_config_t cfg = {.mode = SYMMETRIC,
                         .symm_cipher = AES_128_GCM,
                         .asymm_cipher = ASYMMETRIC_UNSPECIFIED,
                         .digest_algorithm = SHA_256};

  plaintext_t plaintext_in = {.data = (const unsigned char *)"Hello world!",
                              .data_len = 12 + 1,
                              .aad = NULL,
                              .aad_len = 0};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *key = peacemakr_key_new_symmetric(AES_128_GCM, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(SHA_256, ciphertext, &out_size);
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

  peacemakr_key_free(key);
}

void test_wrong_key(symmetric_cipher cipher) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *original_key = peacemakr_key_new_symmetric(cipher, &rand);

  ciphertext_blob_t *ciphertext =
      peacemakr_encrypt(original_key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  uint8_t *key_bytes = NULL;
  size_t key_size = 0;
  peacemakr_key_get_bytes(original_key, &key_bytes, &key_size);
  key_bytes[0] += 1;

  peacemakr_key_t *key = peacemakr_key_new_bytes(cipher, key_bytes, key_size);
  free(key_bytes);

  decrypt_code success = peacemakr_decrypt(key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_FAILED);

  ciphertext_blob_free(ciphertext);
  peacemakr_key_free(original_key);
  peacemakr_key_free(key);
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

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *master_key = peacemakr_key_new_symmetric(AES_256_GCM, &rand);

  for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
    for (int j = SHA_224; j <= SHA_512; ++j) {
      test_master_key_symmetric_algo(master_key, i, j);
      test_password_symmetric_algo(i, j);
    }
  }

  peacemakr_key_free(master_key);
}
