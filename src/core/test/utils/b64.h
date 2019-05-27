//
// Created by Aman LaChapelle on 8/15/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_B64_H
#define PEACEMAKR_CORE_CRYPTO_B64_H

#include <stdint.h>

uint8_t *b64_encode(const uint8_t *in, const size_t len, size_t *enc_len);

uint8_t *b64_decode(const uint8_t *in, const size_t inlen, size_t *outlen);

#endif // PEACEMAKR_CORE_CRYPTO_B64_H
