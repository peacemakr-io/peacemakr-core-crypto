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
#ifdef linux
#include <bsd/stdlib.h>
#else
#include <stdlib.h>
#endif

static inline int fill_rand(unsigned char *buf, size_t num) {
  arc4random_buf(buf, num);
  return 0;
}

static inline const char *rand_err(int err) {
  return "";
}

#endif //PEACEMAKR_CORE_CRYPTO_HELPER_H
