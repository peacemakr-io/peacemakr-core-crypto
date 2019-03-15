//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "Logging.h"

#include <assert.h>
#include <memory.h>
#include <openssl/err.h>

typedef void (*peacemakr_log_cb)(const char *);
static peacemakr_log_cb log_fn = NULL;

void peacemakr_set_log_callback(peacemakr_log_cb l) { log_fn = l; }

static void log_to_stderr(const char *msg) { fprintf(stderr, "%s", msg); }

void log_printf(const char *function_name, int line, const char *fmt, ...) {

  if (log_fn == NULL) {
    log_fn = &log_to_stderr;
  }

  char linenum[4];
  int num_digits = sprintf(linenum, "%d", line);

  const size_t fmt_len = strlen(function_name) + 2 // ": "
                         + num_digits + 3          // " - "
                         + strlen(fmt) + 1;        // null terminator
  char fmt_str[fmt_len];
  memset(fmt_str, 0, fmt_len);

  (void)snprintf(fmt_str, fmt_len, "%s: %d - %s", function_name, line, fmt);

  const size_t max_message_len = 4 * fmt_len;
  char message[max_message_len];
  memset(message, 0, max_message_len);

  va_list argp;
  va_start(argp, fmt);
  vsnprintf(message, max_message_len, fmt_str, argp);
  log_fn(message);
  va_end(argp);
}

void openssl_log(const char *function_name, int line) {

  if (log_fn == NULL) {
    log_fn = &log_to_stderr;
  }

  char linenum[4];
  int num_digits = sprintf(linenum, "%d", line);

  const size_t msg_len = strlen(function_name) + 2 // ": "
                         + num_digits + 3          // " - "
                         + 256                     // error str from openssl
                         + 1 + 1; // null terminator and newline

  char message[msg_len];
  char openssl_error[256];
  memset(openssl_error, 0, 256);
  unsigned long err_no = ERR_get_error();
  ERR_error_string_n(err_no, openssl_error, 256);

  (void)snprintf(message, msg_len, "%s: %d - %s\n", function_name, line,
                 openssl_error);
  log_fn(message);
}
