//
// Created by Aman LaChapelle on 2019-06-07.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#include "Endian.h"

uint32_t bswap(uint32_t input) {
#if defined(__clang__) | defined(__GNUC__)
  return __builtin_bswap32(input);
#else
  return (((input & 0x000000FF) << 24) | ((input & 0x0000FF00) << 8) |
          ((input & 0x00FF0000) >> 8) | ((input & 0xFF000000) >> 24));
#endif // defined(__builtin_bswap32)
}
