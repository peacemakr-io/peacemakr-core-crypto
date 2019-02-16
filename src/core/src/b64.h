//
// Created by Aman LaChapelle on 8/15/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

// From https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/

#ifndef PEACEMAKR_CORE_CRYPTO_B64_H
#define PEACEMAKR_CORE_CRYPTO_B64_H

#include <stdbool.h>
#include <stddef.h>

char *b64_encode(const unsigned char *in, size_t len, size_t *enc_len);

/**
 * Decodes \p in that is of length \p inlen bytes and stores up to \p outlen bytes into \p out.
 * Assumes that \p inlen does not contain a null terminator on \p in.
 */
bool b64_decode(const char *in, size_t inlen, unsigned char *out, size_t outlen);

#endif // PEACEMAKR_CORE_CRYPTO_B64_H
