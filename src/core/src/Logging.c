//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "Logging.h"

#include <memory.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef PEACEMAKR_LOG_LEVEL
#define PEACEMAKR_LOG_LEVEL 0
#endif

static FILE *out_stream = NULL;

void peacemakr_set_log_out_stream(FILE *new_stream) { out_stream = new_stream; }

void log_printf(const char *filename, int line, level_t level, const char *fmt,
                ...) {

  if (level < PEACEMAKR_LOG_LEVEL || PEACEMAKR_LOG_LEVEL > 1 ||
      PEACEMAKR_LOG_LEVEL < 0)
    return;

  char linenum[4];
  int num_digits = sprintf(linenum, "%d", line);

  const size_t fmt_len = strlen(filename) + 2 // ": "
                         + num_digits + 3     // " - "
                         + strlen(fmt) + 1;   // null terminator
  char fmt_str[fmt_len];
  memcpy(fmt_str, filename, strlen(filename));
  memcpy(fmt_str + strlen(filename), ": ", 2);
  memcpy(fmt_str + strlen(filename) + 2, linenum, num_digits);
  memcpy(fmt_str + strlen(filename) + 2 + num_digits, " - ", 3);
  memcpy(fmt_str + strlen(filename) + 2 + num_digits + 3, fmt, strlen(fmt) + 1);

  va_list argp;
  va_start(argp, fmt);
  int rc = vfprintf(out_stream, fmt_str, argp);
  fflush(out_stream); // TODO: remove me?
  if (rc < 0) {
    fprintf(stderr, "error on vfprintf");
  }
  va_end(argp);
}
