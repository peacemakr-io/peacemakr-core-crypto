//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_H
#define PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_H

#include <stdbool.h>
#include <stddef.h>

typedef enum Mode {
#include "OpenSSLModes.def"
} crypto_mode_t;

typedef struct {
  char *cipher_mode;
  size_t secure_heap_size;
} context_config;

typedef struct CryptoContext crypto_context_t;

const char *get_cipher_mode(crypto_mode_t mode);

crypto_context_t *CryptoContext_new();
void CryptoContext_free(crypto_context_t *ctx);

void CryptoContext_init(crypto_context_t *ctx, context_config cfg);
bool CryptoContext_ready(crypto_context_t *ctx);

const char *CryptoContext_get_cipher_mode(crypto_context_t *ctx);

// register calls made into memory and only resolve them at the end?
// CryptoContext_enqueue_malloc(size_t)
// CryptoContext_resolve_malloc()

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_H
