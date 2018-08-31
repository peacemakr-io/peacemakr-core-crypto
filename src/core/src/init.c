//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <crypto.h>
#include <Logging.h>

#ifdef linux
#include <bsd/stdlib.h>
#endif
#include <stdlib.h>
#include <errno.h>


bool peacemakr_init() {
  size_t bufsize = 512; // larger than any key size in bytes
  volatile uint32_t *random_buf = alloca(bufsize);
  // TODO: should this be the linux getrandom syscall?
  for (int i = 0; i < bufsize / sizeof(uint32_t); i++) {
    *(random_buf + i) = arc4random();
  }
  return true;
}


