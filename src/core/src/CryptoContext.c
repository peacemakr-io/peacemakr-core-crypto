//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <CryptoContext.h>

#include <openssl/crypto.h>
#include <stdbool.h>
#include <memory.h>

struct CryptoContext {
  bool m_alloc_ready_;
};

typedef struct CryptoContext crypto_context_t;

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(CryptoContext_, name)

crypto_context_t *API(new)() {
  return malloc(sizeof(crypto_context_t));
}

void API(free) (crypto_context_t *ctx) {
  int rc = -1;
  if (1 == CRYPTO_secure_malloc_initialized()) // already initialized
    rc = CRYPTO_secure_malloc_done();

  switch (rc) {
    case 0: printf("heap not freed"); return;
    case 1: break;
    default: printf("unknown value"); return;
  }

  free(ctx);
}

void API(init)(crypto_context_t *ctx, context_config cfg) {
  int rc = -1;
  if (1 != CRYPTO_secure_malloc_initialized()) // not already initialized
    rc = CRYPTO_secure_malloc_init(cfg.secure_heap_size, sizeof(unsigned char));

  switch (rc) {
    case 0: printf("init failed"); return;
    case 1: break;
    case 2: printf("mmap failed"); return;
    default: printf("unknown value"); return;
  }

  ctx->m_alloc_ready_ = true;
}

bool API(ready)(crypto_context_t *ctx) {
  return (ctx != NULL && ctx->m_alloc_ready_);
}