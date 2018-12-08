//
// Created by Aman LaChapelle on 8/31/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "Logging.h"
#include "crypto.h"

#ifdef linux
#include <bsd/stdlib.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

bool peacemakr_init() {
#ifdef PEACEMAKR_CORE_CRYPTO_NDEBUG
  // To give us unique log files between threads (if needed)
  uint16_t unique_id = (uint16_t)rand(); // has to be less than 6 digits
  char filename[35];
  sprintf(filename, "peacemakr-core-crypto-%d.log", unique_id);
  FILE *log_file = fopen(filename, "w+");
  if (log_file == NULL) {
    printf("Failed to open log file, aborting\n");
    return false;
  }
  peacemakr_set_log_out_stream(log_file);
#else
  peacemakr_set_log_out_stream(stderr);
#endif

  size_t bufsize = 512; // larger than any key size in bytes
  volatile void *random_buf = alloca(bufsize);
  arc4random_buf((void *)random_buf, bufsize);
  return true;
}
