//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_HELPER_H
#define PEACEMAKR_CORE_CRYPTO_HELPER_H

#include <stddef.h>
#ifdef PEACEMAKR_NEEDS_BSD
#include <openssl/rand.h>
void arc4random_buf(void *buf, size_t n) {
  if (1 != RAND_bytes(buf, n)) {
    return;
  }
}
#else
#include <stdlib.h>
#endif

// Don't make assert just swallow everything, actually run the code inside the
// assert
#ifdef NDEBUG
#undef assert
#define assert(e) e
#endif // NDEBUG

static inline int fill_rand(unsigned char *buf, size_t num) {
  arc4random_buf(buf, num);
  return 0;
}

#endif // PEACEMAKR_CORE_CRYPTO_HELPER_H
