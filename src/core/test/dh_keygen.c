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

void test_symmetric_algo(symmetric_cipher symm_cipher,
                         asymmetric_cipher curve) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *my_key = peacemakr_key_new_asymmetric(curve, &rand);
  peacemakr_key_t *peer_key = peacemakr_key_new_asymmetric(curve, &rand);

  peacemakr_key_t *symm_key = peacemakr_key_dh_generate(symm_cipher, my_key, peer_key);

  ciphertext_blob_t *ciphertext =
      peacemakr_encrypt(symm_key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  decrypt_code success =
      peacemakr_decrypt(symm_key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  peacemakr_key_free(symm_key);
  peacemakr_key_free(my_key);
  peacemakr_key_free(peer_key);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }
  for (int curve = ECDH_P256; curve <= ECDH_P521; ++curve) {
    for (int j = AES_128_GCM; j <= CHACHA20_POLY1305; ++j) {
      test_symmetric_algo(j, curve);
    }
  }
}
