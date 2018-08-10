//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_RANDOM_H
#define PEACEMAKR_CORE_CRYPTO_RANDOM_H

#include <stddef.h>

// Must return zero on success
typedef int (*rng_buf)(unsigned char *, size_t);
typedef const char *(*rng_err)(int);

typedef struct {
  rng_buf generator;
  rng_err err;
} random_device_t;

#endif // PEACEMAKR_CORE_CRYPTO_RANDOM_H
