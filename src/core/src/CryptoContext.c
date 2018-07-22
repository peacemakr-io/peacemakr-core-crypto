//
// Created by Aman LaChapelle on 7/22/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

/*
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */

#include <CryptoContext.h>

#include <openssl/crypto.h>
#include <stdbool.h>

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

void API(init)(crypto_context_t *ctx, size_t heap_size) {
  int rc = -1;
  if (1 != CRYPTO_secure_malloc_initialized()) // not already initialized
    rc = CRYPTO_secure_malloc_init(heap_size, sizeof(unsigned char));

  switch (rc) {
    case 0: printf("init failed"); return;
    case 1: break;
    case 2: printf("mmap failed"); return;
    default: printf("unknown value"); return;
  }

  ctx->m_alloc_ready_ = true;
}

bool API(init_called)(crypto_context_t *ctx) {
  return (ctx != NULL && ctx->m_alloc_ready_);
}