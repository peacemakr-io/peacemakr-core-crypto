//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//


#ifndef PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_H
#define PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
  size_t secure_heap_size;
} context_config;

typedef struct CryptoContext crypto_context_t;

crypto_context_t *CryptoContext_new();
void CryptoContext_free(crypto_context_t *ctx);

void CryptoContext_init(crypto_context_t *ctx, context_config cfg);
bool CryptoContext_ready(crypto_context_t *ctx);

// register calls made into memory and only resolve them at the end?
// CryptoContext_enqueue_malloc(size_t)
// CryptoContext_resolve_malloc()


#endif //PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_H
