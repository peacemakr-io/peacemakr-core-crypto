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
#include <stdlib.h>

#include "utils/helper.h"

const char *message = "Hello, world! I'm testing encryption."; // 37 + 1
const char *message_aad = "And I'm AAD";                       // 11 + 1

void test_asymmetric_algo(symmetric_cipher symm_cipher,
                          asymmetric_cipher cipher) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *key =
      peacemakr_key_new_asymmetric(cipher, symm_cipher, &rand);

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

void test_wrong_key(symmetric_cipher symm_cipher, asymmetric_cipher cipher) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *key =
      peacemakr_key_new_asymmetric(cipher, symm_cipher, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  peacemakr_key_t *wrong_key =
      peacemakr_key_new_asymmetric(cipher, symm_cipher, &rand);

  decrypt_code success =
      peacemakr_decrypt(wrong_key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_FAILED);

  ciphertext_blob_free(ciphertext);
  peacemakr_key_free(wrong_key);
  peacemakr_key_free(key);
}

void test_create_key(symmetric_cipher symm_cipher, asymmetric_cipher cipher) {
  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *key =
      peacemakr_key_new_asymmetric(cipher, symm_cipher, &rand);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  // Serialize the key to a pem
  char *pembuf;
  size_t pembufsize;
  assert(peacemakr_key_priv_to_pem(key, &pembuf, &pembufsize));
  peacemakr_key_free(key);

  size_t b64_size = 0;
  uint8_t *serialized = peacemakr_serialize(SHA_512, ciphertext, &b64_size);

  crypto_config_t cfg;
  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(serialized, b64_size, &cfg);
  free(serialized);

  peacemakr_key_t *key_from_pem =
      peacemakr_key_new_pem_priv(cfg.symm_cipher, pembuf, pembufsize);
  free(pembuf);

  decrypt_code result =
      peacemakr_decrypt(key_from_pem, deserialized, &plaintext_out);
  assert(result == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  peacemakr_key_free(key_from_pem);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }
  for (int i = RSA_2048; i <= RSA_4096; ++i) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      test_asymmetric_algo(j, i);
      test_wrong_key(j, i);
      test_create_key(j, i);
    }
  }
}
