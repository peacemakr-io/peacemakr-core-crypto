//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "Logging.h"
#include "crypto.h"

#ifdef PEACEMAKR_NEEDS_BSD
#include <openssl/rand.h>
void arc4random_buf(void *buf, size_t n) {
  if (1 != RAND_bytes(buf, n)) {
    PEACEMAKR_OPENSSL_LOG;
    return;
  }
}
#endif
#include <stdlib.h>

uint32_t get_max_version() {
  return PEACEMAKR_CORE_CRYPTO_VERSION_MAX;
}

uint32_t get_version() {
  return PEACEMAKR_CORE_CRYPTO_VERSION;
}

bool peacemakr_init() {
  size_t bufsize = 512; // larger than any key size in bytes
  volatile void *random_buf = alloca(bufsize);
  arc4random_buf((void *)random_buf, bufsize);
  return true;
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
