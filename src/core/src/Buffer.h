//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_MEMORY_H
#define PEACEMAKR_CORE_CRYPTO_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#include <random.h>

typedef struct Buffer buffer_t;

// Allocates a buffer of zeros - also doesn't allocate anything if size <= 0
buffer_t *Buffer_new(size_t size);
// no-op if buf == NULL
void Buffer_free(buffer_t *buf);

void Buffer_init_rand(buffer_t *buf, random_device_t *rng);

void Buffer_set_bytes(buffer_t *buf, const void *mem, size_t size_bytes);
const uint8_t *Buffer_get_bytes(const buffer_t *buf, size_t *out_size);

const size_t Buffer_get_size(const buffer_t *buf);
void Buffer_set_size(buffer_t *buf, size_t size);

#endif // PEACEMAKR_CORE_CRYPTO_MEMORY_H
