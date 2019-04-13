//
// Created by Aman LaChapelle on 11/6/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

/*
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */

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

void test_algo(plaintext_t plaintext_in, const peacemakr_key_t *key) {

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

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
}

int main() {
  if (!peacemakr_init()) {
    printf("Error initializing");
    return 1;
  }

  size_t bigsize = 1 << 25;

  char *message = calloc(bigsize + 1, sizeof(char));
  message[bigsize] = '\0';
  char *aad = calloc(bigsize + 1, sizeof(char));
  aad[bigsize] = '\0';

  arc4random_buf(message, bigsize);
  arc4random_buf(aad, bigsize);

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = bigsize + 1,
                              .aad = (const unsigned char *)aad,
                              .aad_len = bigsize + 1};

  crypto_config_t asymm_cfg = {.mode = ASYMMETRIC,
                               .asymm_cipher = RSA_4096,
                               .symm_cipher = CHACHA20_POLY1305,
                               .digest_algorithm = SHA_512};

  crypto_config_t symm_cfg = {.mode = SYMMETRIC,
                              .asymm_cipher = NONE,
                              .symm_cipher = CHACHA20_POLY1305,
                              .digest_algorithm = SHA_512};

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *asymm_key = peacemakr_key_new(asymm_cfg, &rand);

  test_algo(plaintext_in, asymm_key);

  peacemakr_key_t *symm_key = peacemakr_key_new(symm_cfg, &rand);

  test_algo(plaintext_in, symm_key);

  peacemakr_key_free(asymm_key);
  peacemakr_key_free(symm_key);

  free(message);
  free(aad);
}
