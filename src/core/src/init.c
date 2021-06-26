//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "Logging.h"
#include "peacemakr/crypto.h"

#ifdef PEACEMAKR_NEEDS_BSD
#include <openssl/rand.h>
void arc4random_buf(void *buf, size_t n) {
  if (1 != RAND_bytes(buf, n)) {
    PEACEMAKR_OPENSSL_LOG;
    return;
  }
}
#endif
#include <openssl/crypto.h>
#include <stdlib.h>

peacemakr_malloc_cb peacemakr_global_malloc = &malloc;
peacemakr_calloc_cb peacemakr_global_calloc = &calloc;
peacemakr_realloc_cb peacemakr_global_realloc = &realloc;
peacemakr_free_cb peacemakr_global_free = &free;

static void *openssl_peacemakr_global_malloc_cb(size_t size, const char *c,
                                                int i) {
  (void)c;
  (void)i;
  return peacemakr_global_malloc(size);
}

static void *openssl_realloc_cb(void *ptr, size_t size, const char *c, int i) {
  (void)c;
  (void)i;
  return peacemakr_global_realloc(ptr, size);
}

static void openssl_free_cb(void *ptr, const char *c, int i) {
  (void)c;
  (void)i;
  return peacemakr_global_free(ptr);
}

bool peacemakr_init() {
  // Init openssl callbacks
  if (1 != CRYPTO_set_mem_functions(&openssl_peacemakr_global_malloc_cb,
                                    &openssl_realloc_cb, &openssl_free_cb)) {
    PEACEMAKR_OPENSSL_LOG;
    return false;
  }

  // Init the RNG
  const size_t bufsize = 512; // larger than any key size in bytes
  volatile uint8_t random_buf[bufsize];
  arc4random_buf((void *)random_buf, bufsize);

  return true;
}

bool peacemakr_init_memory(peacemakr_malloc_cb malloc_cb,
                           peacemakr_calloc_cb calloc_cb,
                           peacemakr_realloc_cb realloc_cb,
                           peacemakr_free_cb free_cb) {
  if (malloc_cb) {
    peacemakr_global_malloc = malloc_cb;
  }

  if (calloc_cb) {
    peacemakr_global_calloc = calloc_cb;
  }

  if (realloc_cb) {
    peacemakr_global_realloc = realloc_cb;
  }

  if (free_cb) {
    peacemakr_global_free = free_cb;
  }

  return peacemakr_init();
}

static int gen_rand(unsigned char *buf, size_t num) {
  arc4random_buf((void *)buf, num);
  return 0;
}
static const char *err(int code) { return "Unknown error code"; }

random_device_t get_default_random_device() {
  random_device_t out;
  out.generator = &gen_rand;
  out.err = &err;

  return out;
}
