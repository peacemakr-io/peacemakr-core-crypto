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

void test_symmetric_algo(symmetric_cipher symm_cipher, const char *pubkey_buf,
                         const size_t pubkey_len, const char *privkey_buf,
                         const size_t privkey_len) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  peacemakr_key_t *pubkey =
      peacemakr_key_new_pem_pub(RSA_4096, pubkey_buf, pubkey_len);
  peacemakr_key_set_symmetric_cipher(pubkey, symm_cipher);
  peacemakr_key_t *privkey =
      peacemakr_key_new_pem_priv(RSA_4096, privkey_buf, privkey_len);
  peacemakr_key_set_symmetric_cipher(privkey, symm_cipher);

  ciphertext_blob_t *ciphertext =
      peacemakr_encrypt(pubkey, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  decrypt_code success = peacemakr_decrypt(privkey, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  peacemakr_key_free(pubkey);
  peacemakr_key_free(privkey);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  random_device_t rand = {.generator = &fill_rand, .err = &rand_err};

  char *privkey;
  char *pubkey;

  size_t priv_len = 0, pub_len = 0;

  peacemakr_key_t *asym_key = peacemakr_key_new_asymmetric(RSA_4096, &rand);

  peacemakr_key_priv_to_pem(asym_key, &privkey, &priv_len);
  peacemakr_key_pub_to_pem(asym_key, &pubkey, &pub_len);

  for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
    test_symmetric_algo(i, pubkey, pub_len, privkey, priv_len);
  }

  free(privkey);
  free(pubkey);

  peacemakr_key_free(asym_key);
}
