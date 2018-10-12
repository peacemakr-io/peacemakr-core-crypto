//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_LOGGING_H
#define PEACEMAKR_CORE_CRYPTO_LOGGING_H

typedef enum { LOG = 0 } level_t;

void log_printf(const char *filename, int line, level_t level, const char *fmt,
                ...);

#define PEACEMAKR_LOG(...) log_printf(__FILE__, __LINE__, LOG, __VA_ARGS__)

#define EXPECT_NOT_NULL_RET(ptr, ...)                                          \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    return NULL;                                                               \
  }
#define EXPECT_NOT_NULL_CLEANUP_RET(ptr, free_call, ...)                       \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    free_call;                                                                 \
    return NULL;                                                               \
  }
#define EXPECT_NOT_NULL_RET_VALUE(ptr, value, ...)                             \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    return value;                                                              \
  }
#define EXPECT_NOT_NULL_RET_NONE(ptr, ...)                                     \
  if (ptr == NULL) {                                                           \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    return;                                                                    \
  }
#define EXPECT_TRUE_RET(condition, ...)                                        \
  if (!(condition)) {                                                          \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    return NULL;                                                               \
  }
#define EXPECT_TRUE_CLEANUP_RET(condition, free_call, ...)                     \
  if (!(condition)) {                                                          \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    free_call;                                                                 \
    return NULL;                                                               \
  }
#define EXPECT_TRUE_RET_NONE(condition, ...)                                   \
  if (!(condition)) {                                                          \
    PEACEMAKR_LOG(__VA_ARGS__);                                                \
    return;                                                                    \
  }
#define OPENSSL_CHECK_RET_VALUE(call, ctx, value)                              \
  if (1 != call) {                                                             \
    PEACEMAKR_LOG("%s failed\n", #call);                                       \
    EVP_CIPHER_CTX_free(ctx);                                                  \
    return value;                                                              \
  }
#define OPENSSL_CHECK_RET_NONE(call, free_call)                                \
  if (1 != call) {                                                             \
    PEACEMAKR_LOG("%s failed\n", #call);                                       \
    free_call;                                                                 \
    return;                                                                    \
  }

#endif // PEACEMAKR_CORE_CRYPTO_LOGGING_H
