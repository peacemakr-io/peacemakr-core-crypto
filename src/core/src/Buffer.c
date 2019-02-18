//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#define __STDC_WANT_LIB_EXT1__ 1
#include <arpa/inet.h>
#include <memory.h>
#include <stdlib.h>

#include "Buffer.h"
#include "Logging.h"

#ifdef PEACEMAKR_NO_MEMSET_S
#ifndef __APPLE__

#include <errno.h>
#include <limits.h>
#include <stdint.h>

#ifndef RSIZE_MAX
#if defined(SIZE_MAX)
#define RSIZE_MAX (SIZE_MAX >> 1)
#elif defined(__LP64__)
#define RSIZE_MAX 0x7fffffffffffffffUL
#else
#define RSIZE_MAX 0x7fffffffU
#endif
#endif

int memset_s(void *restrict v, size_t smax, uint8_t c, size_t n) {
  if (v == NULL || smax > RSIZE_MAX)
    return EINVAL;
  if (n > smax)
    return EINVAL;

  volatile uint8_t *p = v;
  while (smax-- && n--) {
    *p++ = c;
  }

  return 0;
}
#endif // __APPLE__
#endif // PEACEMAKR_NO_MEMSET_S

struct Buffer {
  uint8_t *m_mem_;
  size_t m_size_bytes_;
};

typedef struct Buffer buffer_t;

buffer_t *Buffer_new(const size_t size) {
  // Allocate nothing if size is <= 0
  if (size <= 0) {
    PEACEMAKR_LOG("size passed was <= 0\n");
    return NULL;
  }

  buffer_t *ret = malloc(sizeof(buffer_t));
  EXPECT_NOT_NULL_RET(ret, "Malloc failed!\n");

  ret->m_size_bytes_ = size;

  ret->m_mem_ = calloc(size, sizeof(uint8_t));
  EXPECT_NOT_NULL_CLEANUP_RET(ret->m_mem_, free(ret),
                              "malloc returned nullptr\n");

  return ret;
}

void Buffer_free(buffer_t *buf) {
  if (buf == NULL) {
    return;
  }

  int err = memset_s(buf->m_mem_, buf->m_size_bytes_, 0, buf->m_size_bytes_);
  EXPECT_TRUE_RET_NONE((err == 0),
                       "memset failed, aborting (memory NOT freed)\n");

  free(buf->m_mem_);
  buf->m_mem_ = NULL;

  free(buf);
  buf = NULL;
}

void Buffer_init_rand(buffer_t *buf, random_device_t *rng) {
  EXPECT_NOT_NULL_RET_NONE(buf, "buf was null\n");
  EXPECT_NOT_NULL_RET_NONE(rng, "rng was null\n");

  int rc = rng->generator(buf->m_mem_, buf->m_size_bytes_);
  EXPECT_TRUE_RET_NONE((rc == 0), "rng encountered error, %s\n", rng->err(rc));
}

void Buffer_set_bytes(buffer_t *buf, const void *mem, const size_t size_bytes) {
  EXPECT_NOT_NULL_RET_NONE(buf, "buf was null\n");
  EXPECT_NOT_NULL_RET_NONE(mem, "mem was null\n");

  EXPECT_TRUE_RET_NONE((buf->m_size_bytes_ >= size_bytes),
                       "buffer size less than input size\n");

  // Don't use the passed in size just in case
  memcpy((void *)buf->m_mem_, mem, buf->m_size_bytes_);
}

const uint8_t *Buffer_get_bytes(const buffer_t *buf, size_t *out_size) {
  // If buf is NULL, return NULL
  if (buf == NULL) {
    PEACEMAKR_LOG("buf was NULL\n");
    return NULL;
  }

  if (out_size != NULL) {
    *out_size = buf->m_size_bytes_;
  }

  return buf->m_mem_;
}

uint8_t *Buffer_mutable_bytes(buffer_t *buf) {
  if (buf == NULL) {
    PEACEMAKR_LOG("buf was NULL\n");
    return NULL;
  }
  return buf->m_mem_;
}

const size_t Buffer_get_size(const buffer_t *buf) {
  // If buf is NULL then return 0
  if (buf == NULL) {
    PEACEMAKR_LOG("buf was NULL\n");
    return 0;
  }

  return buf->m_size_bytes_;
}

void Buffer_set_size(buffer_t *buf, const size_t size) {
  EXPECT_NOT_NULL_RET_NONE(buf, "buf was null\n");
  if (buf->m_size_bytes_ == size) {
    return;
  }

  buf->m_mem_ = realloc((void *)buf->m_mem_, size);
  EXPECT_NOT_NULL_RET_NONE(buf->m_mem_, "realloc failed\n");
  buf->m_size_bytes_ = size;
}

size_t Buffer_serialize(const buffer_t *buf, uint8_t *serialized) {
  EXPECT_NOT_NULL_RET_VALUE(serialized, 0, "serialized was null\n");

  if (buf == NULL) {
    memset(serialized, 0, sizeof(uint64_t));
    return sizeof(uint64_t);
  }

  uint64_t buf_len = htonl(buf->m_size_bytes_);
  memcpy(serialized, &buf_len, sizeof(uint64_t));
  memcpy(serialized + sizeof(uint64_t), buf->m_mem_, buf->m_size_bytes_);
  return buf->m_size_bytes_ + sizeof(uint64_t);
}

buffer_t *Buffer_deserialize(const uint8_t *serialized) {
  EXPECT_NOT_NULL_RET(serialized, "serialized was null\n");

  uint64_t buflen = ntohl(*((uint64_t *)serialized));
  buffer_t *out = Buffer_new(buflen);
  if (out != NULL) {
    Buffer_set_bytes(out, serialized + sizeof(uint64_t), buflen);
  }
  return out;
}

size_t Buffer_get_serialized_size(const buffer_t *buf) {
  if (buf == NULL) {
    return sizeof(uint64_t); // we will serialize to zero
  }

  return buf->m_size_bytes_ + sizeof(uint64_t);
}
