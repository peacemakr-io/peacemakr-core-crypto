//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_LOGGING_H
#define PEACEMAKR_CORE_CRYPTO_LOGGING_H

typedef enum { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 } level_t;

void log_printf(const char *filename, int line, level_t level, const char *fmt,
                ...);

#define PEACEMAKR_DEBUG(...) log_printf(__FILE__, __LINE__, DEBUG, __VA_ARGS__)
#define PEACEMAKR_INFO(...) log_printf(__FILE__, __LINE__, INFO, __VA_ARGS__)
#define PEACEMAKR_WARNING(...) log_printf(__FILE__, __LINE__, WARN, __VA_ARGS__)
#define PEACEMAKR_ERROR(...) log_printf(__FILE__, __LINE__, ERROR, __VA_ARGS__)

#endif // PEACEMAKR_CORE_CRYPTO_LOGGING_H
