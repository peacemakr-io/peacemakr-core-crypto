//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_LOGGING_H
#define PEACEMAKR_CORE_CRYPTO_LOGGING_H

#ifndef PEACEMAKR_LOG_LEVEL
#define PEACEMAKR_LOG_LEVEL 2
#endif

void log_printf(const char *filename, int line, const char *fmt, ...);

void openssl_log(const char *filename, int line);

#define PEACEMAKR_LOG(...)                                                     \
  if (PEACEMAKR_LOG_LEVEL != 0)                                                \
    ;                                                                          \
  else                                                                         \
    log_printf(__FUNCTION__, __LINE__, __VA_ARGS__)
#define PEACEMAKR_ERROR(...)                                                   \
  if (PEACEMAKR_LOG_LEVEL > 1)                                                 \
    ;                                                                          \
  else                                                                         \
    log_printf(__FUNCTION__, __LINE__, __VA_ARGS__)

#define PEACEMAKR_OPENSSL_LOG openssl_log(__FUNCTION__, __LINE__)

#define EXPECT_NOT_NULL_RET(ptr, ...)                                          \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    return NULL;                                                               \
  }
#define EXPECT_NOT_NULL_CLEANUP_RET(ptr, free_call, ...)                       \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    free_call;                                                                 \
    return NULL;                                                               \
  }
#define EXPECT_NOT_NULL_CLEANUP_RET_VALUE(ptr, free_call, value, ...)          \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    free_call;                                                                 \
    return value;                                                              \
  }
#define EXPECT_NOT_NULL_RET_VALUE(ptr, value, ...)                             \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    return value;                                                              \
  }
#define EXPECT_NOT_NULL_RET_NONE(ptr, ...)                                     \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    return;                                                                    \
  }
#define EXPECT_TRUE_RET(condition, ...)                                        \
  if (!(condition)) {                                                          \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    return NULL;                                                               \
  }
#define EXPECT_TRUE_CLEANUP_RET(condition, free_call, ...)                     \
  if (!(condition)) {                                                          \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    free_call;                                                                 \
    return NULL;                                                               \
  }
#define EXPECT_TRUE_RET_NONE(condition, ...)                                   \
  if (!(condition)) {                                                          \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    return;                                                                    \
  }
#define EXPECT_TRUE_CLEANUP_RET_NONE(condition, free_call, ...)                \
  if (!(condition)) {                                                          \
    PEACEMAKR_ERROR(__VA_ARGS__);                                              \
    free_call;                                                                 \
    return;                                                                    \
  }
#define OPENSSL_CHECK_RET_VALUE(call, ctx, value)                              \
  if (1 != (call)) {                                                           \
    PEACEMAKR_OPENSSL_LOG;                                                     \
    PEACEMAKR_ERROR("call failed\n");                                          \
    EVP_CIPHER_CTX_free(ctx);                                                  \
    return value;                                                              \
  }
#define OPENSSL_CHECK_RET_NONE(call, free_call)                                \
  if (1 != (call)) {                                                           \
    PEACEMAKR_OPENSSL_LOG;                                                     \
    PEACEMAKR_ERROR("call failed\n");                                          \
    free_call;                                                                 \
    return;                                                                    \
  }

#endif // PEACEMAKR_CORE_CRYPTO_LOGGING_H
