//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include <Logging.h>
#include <crypto.h>

#ifdef linux
#include <bsd/stdlib.h>
#endif
#include <stdio.h>
#include <stdlib.h>

bool peacemakr_init() {
  peacemakr_set_log_out_stream(stderr);

  size_t bufsize = 512; // larger than any key size in bytes
  volatile void *random_buf = alloca(bufsize);
  arc4random_buf((void *)random_buf, bufsize);
  return true;
}
