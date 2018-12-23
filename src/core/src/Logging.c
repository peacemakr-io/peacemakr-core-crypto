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

#ifndef PEACEMAKR_LOG_LEVEL
#define PEACEMAKR_LOG_LEVEL 0
#endif

typedef void (*peacemakr_log_cb)(char *);
static peacemakr_log_cb log_fn = NULL;

void peacemakr_set_log_callback(peacemakr_log_cb l) { log_fn = l; }

static void log_to_stderr(char *msg) { fprintf(stderr, "%s", msg); }

void log_printf(const char *function_name, int line, level_t level,
                const char *fmt, ...) {

  if (log_fn == NULL) {
    log_fn = &log_to_stderr;
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

  char *message = calloc(2 * fmt_len, sizeof(char));

  va_list argp;
  va_start(argp, fmt);
  vsprintf(message, fmt_str, argp);
  log_fn(message);
  va_end(argp);

  free(message);
}

void openssl_log(const char *function_name, int line) {

  if (log_fn == NULL) {
    log_fn = &log_to_stderr;
  }

  char linenum[4];
  int num_digits = sprintf(linenum, "%d", line);

  const size_t fmt_len = strlen(function_name) + 2 // ": "
                         + num_digits + 3          // " - "
                         + 256;                    // error str from openssl

  char fmt_str[fmt_len];
  memcpy(fmt_str, function_name, strlen(function_name));
  memcpy(fmt_str + strlen(function_name), ": ", 2);
  memcpy(fmt_str + strlen(function_name) + 2, linenum, num_digits);
  memcpy(fmt_str + strlen(function_name) + 2 + num_digits, " - ", 3);

  char openssl_error[256];
  memset(openssl_error, 0, 256);
  unsigned long err_no = ERR_get_error();
  ERR_error_string_n(err_no, openssl_error, 256);

  memcpy(fmt_str + strlen(function_name) + 2 + num_digits + 3, openssl_error,
         strlen(openssl_error));

  char *message = calloc(fmt_len + strlen(openssl_error), sizeof(char));
  sprintf(message, "%s\n", fmt_str);
  log_fn(message);
  free(message);
}
