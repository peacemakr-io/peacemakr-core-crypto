//
// Created by Aman LaChapelle on 2019-06-07.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_ENDIAN_H
#define PEACEMAKR_CORE_CRYPTO_ENDIAN_H

#include <stdint.h>

typedef uint32_t length_t;

// Byte swap magic so we have fast bswap32
length_t bswap(length_t input);

// Check for endianness
#if defined(BYTE_ORDER) && defined(LITTLE_ENDIAN)
#define IS_LITTLE_ENDIAN BYTE_ORDER == LITTLE_ENDIAN
#else
#define IS_LITTLE_ENDIAN                                                       \
  (((union {                                                                   \
     unsigned x;                                                               \
     unsigned char c;                                                          \
   }){1})                                                                      \
       .c)
#endif // BYTE_ORDER & LITTLE_ENDIAN

#define ENDIAN_CHECK(x) IS_LITTLE_ENDIAN ? (x) : bswap((x))

#endif // PEACEMAKR_CORE_CRYPTO_ENDIAN_H
