//
// Created by Aman LaChapelle on 2019-02-07.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <arpa/inet.h>
#include <assert.h>
#include <memory.h>
#include <peacemakr/crypto.h>
#include <stdlib.h>

#include "utils/b64.h"
#include "utils/helper.h"

void test_deserialize_garbage() {
  const uint32_t message_len = 253;
  uint8_t garbage_message[message_len];

  fill_rand(garbage_message, message_len);

  crypto_config_t out_cfg = {.mode = SYMMETRIC,
                             .symm_cipher = AES_256_GCM,
                             .digest_algorithm = SHA_512};

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(garbage_message, message_len, &out_cfg);
  assert(deserialized == NULL);
}

void test_deserialize_b64_garbage() {
  const uint32_t message_len = 253;
  uint8_t garbage_message[message_len];

  fill_rand(garbage_message, message_len);

  size_t outlen;
  uint8_t *b64_msg = b64_encode(garbage_message, message_len, &outlen);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(b64_msg, outlen, &out_cfg);
  assert(deserialized == NULL);
  peacemakr_global_free(b64_msg);
}

void test_deserialize_b64_with_magic_garbage() {
  const uint32_t message_len = 253;
  uint8_t garbage_message[message_len];

  fill_rand(garbage_message, message_len);
  // Version number
  uint32_t magic = 1;
  memcpy(garbage_message, &magic, sizeof(uint32_t));

  size_t outlen;
  uint8_t *b64_msg = b64_encode(garbage_message, message_len, &outlen);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(b64_msg, outlen, &out_cfg);
  assert(deserialized == NULL);
  peacemakr_global_free(b64_msg);
}

void test_deserialize_b64_with_magic_and_correct_len_garbage() {
  const uint32_t message_len = 253;
  uint8_t garbage_message[message_len];

  fill_rand(garbage_message, message_len);
  // version number
  uint32_t magic = 1;
  memcpy(garbage_message, &magic, sizeof(uint32_t));
  uint64_t len_until_digest = htonl(message_len - 32);
  memcpy(garbage_message + sizeof(uint32_t), &len_until_digest,
         sizeof(uint64_t));

  size_t outlen;
  uint8_t *b64_msg = b64_encode(garbage_message, message_len, &outlen);

  crypto_config_t out_cfg;

  ciphertext_blob_t *deserialized =
      peacemakr_deserialize(b64_msg, outlen, &out_cfg);
  assert(deserialized == NULL);
  peacemakr_global_free(b64_msg);
}

int main() {
  if (!peacemakr_init()) {
    return 1;
  }

  test_deserialize_garbage();
  test_deserialize_b64_garbage();
  test_deserialize_b64_with_magic_garbage();
  test_deserialize_b64_with_magic_and_correct_len_garbage();
}
