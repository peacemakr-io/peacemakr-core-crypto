//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <CryptoContext.h>
#include <CryptoMemory.h>

#include <stdlib.h>

#include <memory.h>
#include <openssl/crypto.h>

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(SecureBuffer_, name)

struct SecureBuffer {
  uint8_t *m_mem_;
  size_t m_size_bytes_;
  crypto_context_t *m_ctx_;
};

typedef struct SecureBuffer secure_buffer_t;

secure_buffer_t *API(new)(crypto_context_t *ctx, size_t size) {
  if (!CryptoContext_ready(ctx)) {
    printf("context uninitialized or null");
    return NULL;
  }

  if (1 != CRYPTO_secure_malloc_initialized()) {
    printf("secure malloc uninitialized");
    return NULL;
  }

  secure_buffer_t *ret = OPENSSL_secure_zalloc(sizeof(secure_buffer_t));
  ret->m_size_bytes_ = size;
  ret->m_ctx_ = ctx;

  if (size > OPENSSL_MALLOC_MAX_NELEMS(uint8_t)) {
    printf("too many elements requested");
    OPENSSL_secure_clear_free(ret, sizeof(secure_buffer_t));
    return NULL;
  }

  ret->m_mem_ = OPENSSL_secure_zalloc(size);
  if (ret->m_mem_ == NULL) {
    printf("malloc returned nullptr");
    OPENSSL_secure_clear_free(ret, sizeof(secure_buffer_t));
    return NULL;
  }

  return ret;
}

void API(free)(secure_buffer_t *buf) {
  OPENSSL_secure_clear_free(buf->m_mem_, buf->m_size_bytes_);
  OPENSSL_secure_clear_free(buf, sizeof(secure_buffer_t));
}

void API(init_rand)(secure_buffer_t *buf, random_device_t *rng) {
  int rc = rng->generator(buf->m_mem_, buf->m_size_bytes_);
  if (rc != 0) {
    printf("rng encountered error, %s", rng->err(rc));
  }
}

void API(set)(secure_buffer_t *buf, const void *mem, size_t size_bytes) {
  if (buf->m_size_bytes_ != size_bytes) {
    printf("secure buffer size and buffer size mismatch, aborting");
    return;
  }

  // Don't use the passed in size just in case
  memcpy(buf->m_mem_, mem, buf->m_size_bytes_);
}

unsigned char *API(get_bytes)(secure_buffer_t *buf, size_t *out_size) {
  if (out_size != NULL) {
    *out_size = buf->m_size_bytes_;
  }
  return buf->m_mem_;
}

const size_t API(get_size)(secure_buffer_t *buf) { return buf->m_size_bytes_; }

void API(set_size)(secure_buffer_t *buf, size_t size) {
  buf->m_size_bytes_ = size;
}

const crypto_context_t *API(get_ctx)(secure_buffer_t *buf) {
  return buf->m_ctx_;
}
