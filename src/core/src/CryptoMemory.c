//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <CryptoMemory.h>
#include <CryptoContext.h>

#include <stdlib.h>

#include <openssl/crypto.h>

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(SecureBuffer_, name)

struct SecureBuffer {
  unsigned char *m_mem_;
  size_t m_size_bytes_;
  crypto_context_t *m_ctx_;
};

typedef struct SecureBuffer secure_buffer_t;

secure_buffer_t *API(new)(crypto_context_t *ctx, size_t size) {
  if (!CryptoContext_init_called(ctx)) {
    printf("context uninitialized or null");
    return NULL;
  }

  if (1 != CRYPTO_secure_malloc_initialized()) {
    printf("secure malloc uninitialized");
    return NULL;
  }

  secure_buffer_t *ret = OPENSSL_secure_malloc(sizeof(secure_buffer_t));
  ret->m_size_bytes_ = size;
  ret->m_ctx_ = ctx;

  if (size > OPENSSL_MALLOC_MAX_NELEMS(unsigned char)) {
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

void API(init_rand) (secure_buffer_t *buf, random_device_t *rng) {
  int rc = rng->generator(buf->m_mem_, buf->m_size_bytes_);
  if (rc != 0) {
    printf("rng encountered error, %s", rng->err(rc));
  }
}

const unsigned char *API(get_bytes)(secure_buffer_t *buf, size_t *out_size) {
  if (out_size == NULL) {
    printf("out_size is null, terminating");
    return NULL;
  }
  *out_size = buf->m_size_bytes_;
  return buf->m_mem_;
}


