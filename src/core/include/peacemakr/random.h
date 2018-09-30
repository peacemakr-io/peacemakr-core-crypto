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

/**
 * @file peacemakr/random.h
 * Peacemakr core crypto csprng utilities
 */

/**
 * @brief User provided function for filling a random buffer with data.
 *
 * REQUIRES:
 *  - Returns 0 on success
 */
typedef int (*rng_buf)(unsigned char *, size_t);

/**
 * @brief User provided function for interpreting errors in rng_buf
 *
 * REQUIRES:
 *  - Must at least return `""`
 */
typedef const char *(*rng_err)(int);

/**
 * Simple wrapper for user-provided functions to provide a uniform interface to
 * the rest of the crypto lib.
 */
typedef struct {
  rng_buf generator;
  rng_err err;
} random_device_t;

#endif // PEACEMAKR_CORE_CRYPTO_RANDOM_H
