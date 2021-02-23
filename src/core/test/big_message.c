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

void test_algo(plaintext_t plaintext_in, const peacemakr_key_t *key) {

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  decrypt_code success = peacemakr_decrypt(key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  peacemakr_global_free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  peacemakr_global_free((void *)plaintext_out.aad);
}

void *my_malloc(size_t sz) { return calloc(sz, 1); }

int main() {
  // Make this test also check that the init_memory thing works.
  if (!peacemakr_init_memory(&my_malloc, NULL, NULL, NULL)) {
    printf("Error initializing");
    return 1;
  }

  size_t bigsize = 1 << 25;

  char *message = peacemakr_global_calloc(bigsize + 1, sizeof(char));
  char *aad = peacemakr_global_calloc(bigsize + 1, sizeof(char));

  arc4random_buf(message, bigsize);
  arc4random_buf(aad, bigsize);

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = bigsize + 1,
                              .aad = (const unsigned char *)aad,
                              .aad_len = bigsize + 1};

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *asymm_key =
      peacemakr_key_new_asymmetric(RSA_4096, CHACHA20_POLY1305, &rand);

  test_algo(plaintext_in, asymm_key);

  peacemakr_key_t *symm_key =
      peacemakr_key_new_symmetric(CHACHA20_POLY1305, &rand);

  test_algo(plaintext_in, symm_key);

  peacemakr_key_free(asymm_key);
  peacemakr_key_free(symm_key);

  peacemakr_global_free(message);
  peacemakr_global_free(aad);
}
