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

#include "Endian.h"

typedef struct Buffer buffer_t;

// Allocates a buffer of zeros - also doesn't allocate anything if size <= 0
buffer_t *buffer_new(const size_t size);
// no-op if buf == NULL
void buffer_free(buffer_t *buf);

void buffer_init_rand(buffer_t *buf, random_device_t *rng);

void buffer_set_bytes(buffer_t *buf, const void *mem, const size_t size_bytes);
const uint8_t *buffer_get_bytes(const buffer_t *buf, size_t *out_size);
uint8_t *buffer_mutable_bytes(buffer_t *buf);

const size_t buffer_get_size(const buffer_t *buf);
void buffer_set_size(buffer_t *buf, const size_t size);

length_t buffer_serialize(const buffer_t *buf, uint8_t *serialized);
buffer_t *buffer_deserialize(const uint8_t *serialized);
length_t buffer_get_serialized_size(const buffer_t *buf);

#endif // PEACEMAKR_CORE_CRYPTO_MEMORY_H
