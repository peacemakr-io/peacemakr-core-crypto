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
#include <stdio.h>

#include "test_helper.h"

const char *message = "Hello, world! I'm testing encryption."; // 37 + 1
const char *message_aad = "And I'm AAD"; // 11 + 1

void test_symmetric_algo(symmetric_cipher symm_cipher,
                         const char *pubkey_buf, const size_t pubkey_len,
                         const char *privkey_buf, const size_t privkey_len) {
  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .asymm_cipher = RSA_4096,
          .symm_cipher = symm_cipher,
          .digest_algorithm = SHA_512
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

  peacemakr_key_t *pubkey = PeacemakrKey_new_pem_pub(cfg, pubkey_buf, pubkey_len);
  peacemakr_key_t *privkey = PeacemakrKey_new_pem_priv(cfg, privkey_buf, privkey_len);

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(pubkey, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  decrypt_code success = peacemakr_decrypt(privkey, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data, (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad, (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  free((void *)plaintext_out.aad);

  PeacemakrKey_free(pubkey);
  PeacemakrKey_free(privkey);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  crypto_config_t cfg = {
          .mode = ASYMMETRIC,
          .asymm_cipher = RSA_4096,
          .symm_cipher = CHACHA20_POLY1305,
          .digest_algorithm = SHA_512
  };

  random_device_t rand = {
          .generator = &fill_rand,
          .err = &rand_err
  };

  char *privkey;
  char *pubkey;

  size_t priv_len = 0, pub_len = 0;

  peacemakr_key_t *asym_key = PeacemakrKey_new(cfg, &rand);

  PeacemakrKey_priv_to_pem(asym_key, &privkey, &priv_len);
  PeacemakrKey_pub_to_pem(asym_key, &pubkey, &pub_len);

  for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
    test_symmetric_algo(i, pubkey, pub_len, privkey, priv_len);
  }
}
