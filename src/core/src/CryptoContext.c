//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <CryptoContext.h>

#include <memory.h>
#include <openssl/crypto.h>
#include <stdbool.h>

struct CryptoContext {
  char *m_cipher_mode_;
  bool m_alloc_ready_;
};

const char *evp_cipher_modes[] = {
#include "OpenSSLModeStrings.def"
};

const char *get_cipher_mode(crypto_mode_t mode) {
  return evp_cipher_modes[(uint32_t)mode];
}

typedef struct CryptoContext crypto_context_t;

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(CryptoContext_, name)

crypto_context_t *API(new)() { return malloc(sizeof(crypto_context_t)); }

void API(free)(crypto_context_t *ctx) {
  int rc = -1;
  if (1 == CRYPTO_secure_malloc_initialized()) // already initialized
    rc = CRYPTO_secure_malloc_done();

  switch (rc) {
  case 0:
    printf("heap not freed");
    return;
  case 1:
    break;
  default:
    printf("unknown value");
    return;
  }

  free(ctx);
}

void API(init)(crypto_context_t *ctx, context_config cfg) {
  int rc = -1;
  if (1 != CRYPTO_secure_malloc_initialized()) // not already initialized
    rc = CRYPTO_secure_malloc_init(cfg.secure_heap_size, sizeof(unsigned char));

  switch (rc) {
  case 0:
    printf("init failed");
    return;
  case 1:
    break;
  case 2:
    printf("mmap failed");
    return;
  default:
    printf("unknown value");
    return;
  }

  ctx->m_cipher_mode_ = malloc(strlen(cfg.cipher_mode));
  strncpy(ctx->m_cipher_mode_, cfg.cipher_mode, strlen(cfg.cipher_mode));

  ctx->m_alloc_ready_ = true;
}

bool API(ready)(crypto_context_t *ctx) {
  return (ctx != NULL && ctx->m_alloc_ready_);
}

const char *API(get_cipher_mode)(crypto_context_t *ctx) {
  return ctx->m_cipher_mode_;
}