//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include <Buffer.h>
#include <Logging.h>

#define __STDC_WANT_LIB_EXT1__ 1
#include <memory.h>
#include <stddef.h>
#include <stdlib.h>

#include <openssl/crypto.h>

#define RETURN_VOID_IF_ARG_IS_NULL(arg)                                        \
  if ((arg) == NULL) {                                                         \
    PEACEMAKR_ERROR("arg %s is null\n", #arg);                                 \
    return;                                                                    \
  }

#define RETURN_VALUE_IF_ARG_IS_NULL(arg, retval)                               \
  if ((arg) == NULL) {                                                         \
    PEACEMAKR_ERROR("arg %s is null, %s %s\n", #arg);                          \
    return (retval);                                                           \
  }

#ifdef PEACEMAKR_NO_MEMSET_S

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

  EXPECT_TRUE_RET((size > 0), "size passed was <= 0\n")

  ret->m_size_bytes_ = size;

  ret->m_mem_ = calloc(size, sizeof(uint8_t));
  EXPECT_NOT_NULL_CLEANUP_RET(ret->m_mem_, free(ret), "malloc returned nullptr\n");

  return ret;
}

void API(free)(buffer_t *buf) {
  EXPECT_NOT_NULL_RET_NONE(buf, "buf was null, no-op\n");

  int err = memset_s(buf->m_mem_, buf->m_size_bytes_, 0, buf->m_size_bytes_);
  EXPECT_TRUE_RET_NONE((err == 0), "memset failed, aborting (memory NOT freed)\n");

  free(buf->m_mem_);
  buf->m_mem_ = NULL;

  free(buf);
  buf = NULL;
}

void API(init_rand)(buffer_t *buf, random_device_t *rng) {
  RETURN_VOID_IF_ARG_IS_NULL(buf);
  RETURN_VOID_IF_ARG_IS_NULL(rng);

  int rc = rng->generator(buf->m_mem_, buf->m_size_bytes_);
  EXPECT_TRUE_RET_NONE((rc == 0), "rng encountered error, %s\n", rng->err(rc));
}

void API(set_bytes)(buffer_t *buf, const void *mem, size_t size_bytes) {
  RETURN_VOID_IF_ARG_IS_NULL(buf);
  RETURN_VOID_IF_ARG_IS_NULL(mem);

  EXPECT_TRUE_RET_NONE((buf->m_size_bytes_ >= size_bytes), "buffer size less than input size\n");

  // Don't use the passed in size just in case
  memcpy((void *)buf->m_mem_, mem, buf->m_size_bytes_);
}

const uint8_t *API(get_bytes)(const buffer_t *buf, size_t *out_size) {
  RETURN_VALUE_IF_ARG_IS_NULL(buf, NULL);

  if (out_size != NULL) {
    *out_size = buf->m_size_bytes_;
  }

  return buf->m_mem_;
}

const size_t API(get_size)(const buffer_t *buf) {
  RETURN_VALUE_IF_ARG_IS_NULL(buf, 0);

  return buf->m_size_bytes_;
}

void API(set_size)(buffer_t *buf, size_t size) {
  RETURN_VOID_IF_ARG_IS_NULL(buf);

  buf->m_size_bytes_ = size;
}
