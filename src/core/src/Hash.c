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

uint8_t *peacemakr_hmac(const message_digest_algorithm digest_algorithm,
                        const peacemakr_key_t *master_key, const uint8_t *buf,
                        const size_t buf_len, size_t *out_bytes) {

  EXPECT_NOT_NULL_RET(master_key, "Master key was NULL\n")
  const buffer_t *master_key_buf = peacemakr_key_symmetric(master_key);
  const size_t master_keylen = buffer_get_size(master_key_buf);
  EXPECT_TRUE_RET((master_keylen <= INT_MAX),
                  "Length of passed master key is greater than INT_MAX\n")
  EXPECT_TRUE_RET((buf != NULL && buf_len > 0),
                  "buf is null or its length was 0\n")

  // Generate the output
  uint8_t *result = calloc(get_digest_len(digest_algorithm) / sizeof(uint8_t),
                           sizeof(uint8_t));
  uint32_t result_len = 0;

  const uint8_t *master_key_bytes = buffer_get_bytes(master_key_buf, NULL);

  HMAC(parse_digest(digest_algorithm), master_key_bytes, (int)master_keylen,
       buf, buf_len, result, &result_len);

  if (out_bytes != NULL) {
    *out_bytes = result_len;
  }

  return result;
}
