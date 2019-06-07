//
// Created by Aman LaChapelle on 2019-06-07.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

/*
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */


#ifndef PEACEMAKR_CORE_CRYPTO_ENDIAN_H
#define PEACEMAKR_CORE_CRYPTO_ENDIAN_H

typedef uint32_t length_t;

// Byte swap magic so we have fast bswap32
#ifdef linux
#include <byteswap.h>
#else // linux
static length_t bswap(length_t input) {
#if defined(__clang__) | defined(__GNUC__)
  return __builtin_bswap32(input);
#else
  return (((input & 0x000000FF) << 24) | ((input & 0x0000FF00) << 8) |
          ((input & 0x00FF0000) >> 8) | ((input & 0xFF000000) >> 24));
#endif // defined(__builtin_bswap32)
}
#endif // linux

// Check for endianness
#if defined(BYTE_ORDER) & defined(LITTLE_ENDIAN)
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

#endif //PEACEMAKR_CORE_CRYPTO_ENDIAN_H
