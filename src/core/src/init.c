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


bool peacemakr_init() {
  size_t bufsize = 512; // larger than any key size in bytes
  volatile void *random_buf = alloca(bufsize);
  // TODO: should this be the linux getrandom syscall?
  arc4random_buf(random_buf, bufsize);
  return true;
}


