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

ciphertext_blob_t *encrypt(symmetric_cipher symm_cipher,
                           asymmetric_cipher curve, const char *pubkey_buf,
                           const size_t pubkey_len, const char *privkey_buf,
                           const size_t privkey_len) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *pubkey =
      peacemakr_key_new_pem_pub(SYMMETRIC_UNSPECIFIED, pubkey_buf, pubkey_len);
  peacemakr_key_t *privkey = peacemakr_key_new_pem_priv(
      SYMMETRIC_UNSPECIFIED, privkey_buf, privkey_len);

  peacemakr_key_t *sec_key =
      peacemakr_key_dh_generate(symm_cipher, privkey, pubkey);

  ciphertext_blob_t *ciphertext =
      peacemakr_encrypt(sec_key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  peacemakr_key_free(sec_key);
  peacemakr_key_free(pubkey);
  peacemakr_key_free(privkey);

  return ciphertext;
}

void decrypt(symmetric_cipher symm_cipher, asymmetric_cipher curve,
             const char *pubkey_buf, const size_t pubkey_len,
             const char *privkey_buf, const size_t privkey_len,
             ciphertext_blob_t *ciphertext) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  peacemakr_key_t *pubkey =
      peacemakr_key_new_pem_pub(SYMMETRIC_UNSPECIFIED, pubkey_buf, pubkey_len);
  peacemakr_key_t *privkey = peacemakr_key_new_pem_priv(
      SYMMETRIC_UNSPECIFIED, privkey_buf, privkey_len);

  peacemakr_key_t *sec_key =
      peacemakr_key_dh_generate(symm_cipher, privkey, pubkey);

  plaintext_t plaintext_out;

  decrypt_code success = peacemakr_decrypt(sec_key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  peacemakr_global_free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  peacemakr_global_free((void *)plaintext_out.aad);

  peacemakr_key_free(sec_key);
  peacemakr_key_free(pubkey);
  peacemakr_key_free(privkey);
}

void test_symmetric_algo(symmetric_cipher symm_cipher, asymmetric_cipher curve,
                         const char *pubkey_buf, const size_t pubkey_len,
                         const char *privkey_buf, const size_t privkey_len) {

  plaintext_t plaintext_in = {.data = (const unsigned char *)message,
                              .data_len = strlen(message) + 1,
                              .aad = (const unsigned char *)message_aad,
                              .aad_len = strlen(message_aad) + 1};

  plaintext_t plaintext_out;

  random_device_t rand = get_default_random_device();

  peacemakr_key_t *pubkey =
      peacemakr_key_new_pem_pub(SYMMETRIC_UNSPECIFIED, pubkey_buf, pubkey_len);
  peacemakr_key_t *privkey = peacemakr_key_new_pem_priv(
      SYMMETRIC_UNSPECIFIED, privkey_buf, privkey_len);

  peacemakr_key_t *sec_key =
      peacemakr_key_dh_generate(symm_cipher, privkey, pubkey);

  ciphertext_blob_t *ciphertext =
      peacemakr_encrypt(sec_key, &plaintext_in, &rand);
  assert(ciphertext != NULL);

  decrypt_code success = peacemakr_decrypt(sec_key, ciphertext, &plaintext_out);

  assert(success == DECRYPT_SUCCESS);

  assert(strncmp((const char *)plaintext_out.data,
                 (const char *)plaintext_in.data, plaintext_in.data_len) == 0);
  peacemakr_global_free((void *)plaintext_out.data);
  assert(strncmp((const char *)plaintext_out.aad,
                 (const char *)plaintext_in.aad, plaintext_in.aad_len) == 0);
  peacemakr_global_free((void *)plaintext_out.aad);

  peacemakr_key_free(sec_key);
  peacemakr_key_free(pubkey);
  peacemakr_key_free(privkey);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  for (int curve = ECDH_P256; curve <= ECDH_SECP256K1; ++curve) {

    random_device_t rand = get_default_random_device();

    char *my_privkey, *peer_privkey;
    char *my_pubkey, *peer_pubkey;

    size_t priv_len = 0, pub_len = 0;

    peacemakr_key_t *my_key =
        peacemakr_key_new_asymmetric(curve, SYMMETRIC_UNSPECIFIED, &rand);
    peacemakr_key_t *peer_key =
        peacemakr_key_new_asymmetric(curve, SYMMETRIC_UNSPECIFIED, &rand);

    peacemakr_key_priv_to_pem(my_key, &my_privkey, &priv_len);
    peacemakr_key_pub_to_pem(peer_key, &peer_pubkey, &pub_len);

    peacemakr_key_priv_to_pem(peer_key, &peer_privkey, &priv_len);
    peacemakr_key_pub_to_pem(my_key, &my_pubkey, &pub_len);

    for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
      test_symmetric_algo(i, curve, peer_pubkey, pub_len, my_privkey, priv_len);
    }

    for (int i = AES_128_GCM; i <= CHACHA20_POLY1305; ++i) {
      ciphertext_blob_t *encrypted =
          encrypt(i, curve, peer_pubkey, pub_len, my_privkey, priv_len);
      decrypt(i, curve, my_pubkey, pub_len, peer_privkey, priv_len, encrypted);
    }

    free(my_privkey);
    free(my_pubkey);
    free(peer_privkey);
    free(peer_pubkey);

    peacemakr_key_free(my_key);
    peacemakr_key_free(peer_key);
  }
}
