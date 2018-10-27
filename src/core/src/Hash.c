//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "Logging.h"
#include "crypto.h"

#include "Buffer.h"
#include "EVPHelper.h"
#include "Key.h"

#include <openssl/hmac.h>

uint8_t *peacemakr_hmac_256(const peacemakr_key_t *master_key,
                            const uint8_t *buf, const size_t buf_len) {

  EXPECT_NOT_NULL_RET(master_key, "Master key was NULL\n");
  const buffer_t *master_key_buf = PeacemakrKey_symmetric(master_key);
  size_t master_keylen = Buffer_get_size(master_key_buf);
  EXPECT_TRUE_RET((master_keylen <= INT_MAX),
                  "Length of passed master key is greater than INT_MAX\n");
  EXPECT_TRUE_RET((buf != NULL && buf_len > 0),
                  "buf is null or its length was 0\n");

  // Generate the key
  uint8_t *result = calloc(256 / sizeof(uint8_t), sizeof(uint8_t));
  uint32_t result_len = 0;
  // Use HMAC SHA256 to generate the key using the master key and the key id
  const uint8_t *master_key_bytes = Buffer_get_bytes(master_key_buf, NULL);
  HMAC(EVP_sha256(), master_key_bytes, (int)master_keylen, buf, buf_len, result,
       &result_len);

  return result;
}
