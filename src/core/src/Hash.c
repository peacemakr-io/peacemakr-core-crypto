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

  EXPECT_NOT_NULL_RET(master_key, "Master key was NULL\n");
  const buffer_t *master_key_buf = PeacemakrKey_symmetric(master_key);
  size_t master_keylen = Buffer_get_size(master_key_buf);
  EXPECT_TRUE_RET((master_keylen <= INT_MAX),
                  "Length of passed master key is greater than INT_MAX\n");
  EXPECT_TRUE_RET((buf != NULL && buf_len > 0),
                  "buf is null or its length was 0\n");

  // Generate the key
  uint8_t *result = calloc(get_digest_len(digest_algorithm) / sizeof(uint8_t),
                           sizeof(uint8_t));
  uint32_t result_len = 0;

  const uint8_t *master_key_bytes = Buffer_get_bytes(master_key_buf, NULL);
  // Easy path if there's not much data
  if (buf_len <= INT_MAX) {
    HMAC(parse_digest(digest_algorithm), master_key_bytes, (int)master_keylen,
         buf, buf_len, result, &result_len);
  }
  // Hard path if there's too much data to fit in one chunk
  else {
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, master_key_bytes, (int)master_keylen,
                 parse_digest(digest_algorithm), NULL);

    int rc = 0;
    uint8_t *buffer_ptr = (uint8_t *)&buf[0];
    for (int i = 0; i < buf_len; i += (INT_MAX >> 1)) {
      rc = HMAC_Update(ctx, buffer_ptr, (INT_MAX >> 1));
      if (rc != 1) {
        PEACEMAKR_LOG("HMAC_Update failed with code %d", rc);
        HMAC_CTX_free(ctx);
        return NULL;
      }
      buffer_ptr += (INT_MAX >> 1);
    }

    if (out_bytes != NULL) {
      HMAC_Final(ctx, result, (unsigned int *)out_bytes);
    } else {
      HMAC_Final(ctx, result, NULL);
    }

    HMAC_CTX_free(ctx);
  }

  return result;
}
