//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//


#ifndef PEACEMAKR_CORE_CRYPTO_CRYPTOMEMORY_H
#define PEACEMAKR_CORE_CRYPTO_CRYPTOMEMORY_H

#include <CryptoContext.h>

#include <stddef.h>

// Must return zero on success
typedef int (*rng_buf)(unsigned char *, size_t);
typedef const char *(*rng_err)(int);

typedef struct {
  rng_buf generator;
  rng_err err;
} random_device_t;

typedef struct SecureBuffer secure_buffer_t;

// Allocates a buffer of zeros
secure_buffer_t *SecureBuffer_new(crypto_context_t *, size_t);
void SecureBuffer_free(secure_buffer_t *);

void SecureBuffer_init_rand(secure_buffer_t *, random_device_t *);

void SecureBuffer_set_bytes(secure_buffer_t *, const void *, size_t);

const unsigned char *SecureBuffer_get_bytes(secure_buffer_t *, size_t *);
const size_t SecureBuffer_get_size(secure_buffer_t *);

#endif //PEACEMAKR_CORE_CRYPTO_CRYPTOMEMORY_H
