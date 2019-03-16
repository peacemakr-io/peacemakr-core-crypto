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

  peacemakr_key_t *key = PeacemakrKey_new(cfg, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  peacemakr_sign(key, &plaintext_in, ciphertext);
  assert(ciphertext != NULL);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(ciphertext, &out_size);
  assert(serialized != NULL);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(serialized, out_size, &out_cfg);

  free(serialized);

  decrypt_code success = peacemakr_decrypt(key, deserialized, &plaintext_out);
  assert(success == DECRYPT_NEED_VERIFY);

  assert(peacemakr_verify(key, &plaintext_out, deserialized));

  assert(out_cfg.mode == cfg.mode && out_cfg.asymm_cipher == cfg.asymm_cipher &&
         out_cfg.symm_cipher == cfg.symm_cipher &&
         out_cfg.digest_algorithm == cfg.digest_algorithm);

  assert(success);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(key);
}

void test_asymmetric_algo(symmetric_cipher cipher,
                          asymmetric_cipher asymmcipher) {

  crypto_config_t cfg = {.mode = ASYMMETRIC,
                         .symm_cipher = cipher,
                         .asymm_cipher = asymmcipher,
                         .digest_algorithm = SHA_512};

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *mykey = PeacemakrKey_new(cfg, &rand);
  peacemakr_key_t *peerkey = PeacemakrKey_new(cfg, &rand);
  // Set up the key
  peacemakr_key_t *key = (asymmcipher >= ECDH_P256) ? PeacemakrKey_dh_generate(mykey, peerkey) : mykey;
  cfg = PeacemakrKey_get_config(key);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);
  if (asymmcipher >= ECDH_P256) {
    peacemakr_sign(mykey, &plaintext_in, ciphertext);
  } else {
    peacemakr_sign(key, &plaintext_in, ciphertext);
  }

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

  assert(success == DECRYPT_NEED_VERIFY);
  if (asymmcipher >= ECDH_P256) {
    assert(peacemakr_verify(mykey, &plaintext_out, deserialized));
  } else {
    assert(peacemakr_verify(key, &plaintext_out, deserialized));
  }

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(mykey);
  PeacemakrKey_free(peerkey);
  if (asymmcipher >= ECDH_P256) {
    PeacemakrKey_free(key);
  }
}

void test_symmetric_algo_x_sign(symmetric_cipher cipher) {
  crypto_config_t cfg = {
      .mode = SYMMETRIC, .symm_cipher = cipher, .digest_algorithm = SHA_512};

  crypto_config_t asymm_cfg = {.mode = ASYMMETRIC,
                               .asymm_cipher = RSA_4096,
                               .symm_cipher = cipher,
                               .digest_algorithm = SHA_512};

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *key = PeacemakrKey_new(cfg, &rand);
  peacemakr_key_t *sign_key = PeacemakrKey_new(asymm_cfg, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  // Sign with asymmetric key
  peacemakr_sign(sign_key, &plaintext_in, ciphertext);
  assert(ciphertext != NULL);

  size_t out_size = 0;
  uint8_t *serialized = peacemakr_serialize(ciphertext, &out_size);
  assert(serialized != NULL);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(serialized, out_size, &out_cfg);

  free(serialized);

  decrypt_code success = peacemakr_decrypt(key, deserialized, &plaintext_out);
  assert(success == DECRYPT_NEED_VERIFY);

  // Verify with that asymmetric key
  assert(peacemakr_verify(sign_key, &plaintext_out, deserialized));

  assert(out_cfg.mode == cfg.mode && out_cfg.asymm_cipher == cfg.asymm_cipher &&
         out_cfg.symm_cipher == cfg.symm_cipher &&
         out_cfg.digest_algorithm == cfg.digest_algorithm);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(key);
  PeacemakrKey_free(sign_key);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
    test_symmetric_algo(i);
    test_symmetric_algo_x_sign(i);
  }

  for (int i = RSA_2048; i <= ECDH_P521; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      test_asymmetric_algo(j, i);
    }
  }
}
