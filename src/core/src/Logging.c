//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "Logging.h"

#include <memory.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#ifndef PEACEMAKR_LOG_LEVEL
#define PEACEMAKR_LOG_LEVEL 0
#endif

static FILE *out_stream = NULL;

void peacemakr_set_log_out_stream(FILE *new_stream) { out_stream = new_stream; }

void log_printf(const char *function_name, int line, level_t level,
                const char *fmt, ...) {

  if (out_stream == NULL) {
    out_stream = stderr;
  }

  char linenum[4];
  int num_digits = sprintf(linenum, "%d", line);

  const size_t fmt_len = strlen(function_name) + 2 // ": "
                         + num_digits + 3          // " - "
                         + strlen(fmt) + 1;        // null terminator
  char fmt_str[fmt_len];
  memcpy(fmt_str, function_name, strlen(function_name));
  memcpy(fmt_str + strlen(function_name), ": ", 2);
  memcpy(fmt_str + strlen(function_name) + 2, linenum, num_digits);
  memcpy(fmt_str + strlen(function_name) + 2 + num_digits, " - ", 3);
  memcpy(fmt_str + strlen(function_name) + 2 + num_digits + 3, fmt,
         strlen(fmt) + 1);

  va_list argp;
  va_start(argp, fmt);
  int rc = vfprintf(out_stream, fmt_str, argp);
  fflush(out_stream); // we just flush the out_stream since it's a log line
  if (rc < 0) {
    fprintf(stderr, "error on vfprintf");
  }
  va_end(argp);
}

void openssl_log(const char *function_name, int line) {

  if (out_stream == NULL) {
    out_stream = stderr;
  }

  char linenum[4];
  int num_digits = sprintf(linenum, "%d", line);

  const size_t fmt_len = strlen(function_name) + 2 // ": "
                         + num_digits + 3;         // " - "

  char fmt_str[fmt_len];
  memcpy(fmt_str, function_name, strlen(function_name));
  memcpy(fmt_str + strlen(function_name), ": ", 2);
  memcpy(fmt_str + strlen(function_name) + 2, linenum, num_digits);
  memcpy(fmt_str + strlen(function_name) + 2 + num_digits, " - ", 3);

  fprintf(out_stream, "%s\n", fmt_str);
  ERR_print_errors_fp(out_stream);
  fflush(out_stream);
}
