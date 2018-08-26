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

  ciphertext_blob_t *ciphertext = peacemakr_encrypt(cfg, pubkey, &plaintext_in, &rand);
  assert(ciphertext != NULL);
  PeacemakrKey_free(pubkey);

  peacemakr_key_t *privkey = PeacemakrKey_new_pem_priv(cfg, privkey_buf, privkey_len);
  bool success = peacemakr_decrypt(privkey, ciphertext, &plaintext_out);

  assert(success);

  assert(strncmp((const char *)plaintext_out.data, (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  assert(strncmp((const char *)plaintext_out.aad, (const char *)plaintext_in.aad, plaintext_in.data_len) == 0);

  PeacemakrKey_free(privkey);
}

int main() {
  char *privkey;
  char *pubkey;

  size_t priv_len, pub_len;

  FILE *priv = fopen("../../../../src/core/test/resources/test_keypair.pem", "r");

  if (priv) {
    // Seek the last byte of the file
    fseek(priv, 0, SEEK_END);
    // Offset from the first to the last byte, or in other words, filesize
    priv_len = (size_t)ftell(priv);
    // go back to the start of the file
    rewind(priv);

    privkey = alloca(priv_len+1);

    long read_size = fread(privkey, sizeof(char), priv_len, priv);

    assert(read_size == priv_len);

    privkey[priv_len] = '\0';

    fclose(priv);
  } else {
    printf("Opening pem file priv failed");
    return 1;
  }

  FILE *pub = fopen("../../../../src/core/test/resources/test_publickey.pem", "r");

  if (pub) {
    // Seek the last byte of the file
    fseek(pub, 0, SEEK_END);
    // Offset from the first to the last byte, or in other words, filesize
    pub_len = (size_t)ftell(pub);
    // go back to the start of the file
    rewind(pub);

    pubkey = alloca(pub_len+1);

    long read_size = fread(pubkey, sizeof(char), pub_len, pub);

    assert(read_size == pub_len);

    pubkey[pub_len] = '\0';

    fclose(pub);
  } else {
    printf("Opening pem file pub failed");
    return 1;
  }

  for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
    test_symmetric_algo(i, pubkey, pub_len, privkey, priv_len);
  }
}
