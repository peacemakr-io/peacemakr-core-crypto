//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>

#define __STDC_WANT_LIB_EXT1__ 1
#include <memory.h>
#include <stddef.h>
#include <stdlib.h>

#include <openssl/crypto.h>

#ifdef PEACEMAKR_NO_MEMSET_S

#include <stdint.h>
#include <errno.h>
#include <limits.h>

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
  int ret = 0;

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

#endif

#define GLUE(prefix, name) prefix##name
#define API(name) GLUE(Buffer_, name)

struct Buffer {
  uint8_t *m_mem_;
  size_t m_size_bytes_;
};

typedef struct Buffer buffer_t;

buffer_t *API(new)(size_t size) {
  buffer_t *ret = malloc(sizeof(buffer_t));
  ret->m_size_bytes_ = size;

  ret->m_mem_ = calloc(size, sizeof(uint8_t));
  if (ret->m_mem_ == NULL) {
    printf("malloc returned nullptr");
    free(ret);
    return NULL;
  }

  return ret;
}

void API(free)(buffer_t *buf) {
  if (buf == NULL) {
    printf("invalid argument buf");
    return;
  }

  int err = memset_s(buf->m_mem_, buf->m_size_bytes_, 0, buf->m_size_bytes_);
  if (err != 0) {
    printf("memset failed, aborting (memory NOT freed)");
  }
  free(buf->m_mem_);
  buf->m_mem_ = NULL;

  free(buf);
  buf = NULL;
}

void API(init_rand)(buffer_t *buf, random_device_t *rng) {
  if (buf == NULL) {
    printf("invalid argument buf");
    return;
  }

  int rc = rng->generator(buf->m_mem_, buf->m_size_bytes_);
  if (rc != 0) {
    printf("rng encountered error, %s", rng->err(rc));
  }
}

void API(set_bytes)(buffer_t *buf, const void *mem, size_t size_bytes) {
  if (buf == NULL) {
    printf("invalid argument buf");
    return;
  }

  if (mem == NULL) {
    printf("invalid argument mem");
    return;
  }

  if (buf->m_size_bytes_ < size_bytes) {
    printf("buffer size less than input size");
    return;
  }

  // Don't use the passed in size just in case
  memcpy((void *)buf->m_mem_, mem, buf->m_size_bytes_);
}

unsigned char *API(get_bytes)(const buffer_t *buf, size_t *out_size) {
  if (buf == NULL) {
    printf("invalid argument buf");
    return NULL;
  }

  if (out_size != NULL) {
    *out_size = buf->m_size_bytes_;
  }

  return buf->m_mem_;
}

const size_t API(get_size)(const buffer_t *buf) {
  if (buf == NULL) {
    printf("invalid argument buf");
    return 0;
  }

  return buf->m_size_bytes_;
}

void API(set_size)(buffer_t *buf, size_t size) {
  if (buf == NULL) {
    printf("invalid argument buf");
    return;
  }

  buf->m_size_bytes_ = size;
}
