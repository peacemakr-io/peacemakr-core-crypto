//
// Created by Aman LaChapelle on 8/11/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_KEY_H
#define PEACEMAKR_CORE_CRYPTO_KEY_H

#include "Buffer.h"
#include "peacemakr/crypto.h"

#include <openssl/ossl_typ.h>
#include <stddef.h>

typedef struct PeacemakrKey peacemakr_key_t;

const buffer_t *peacemakr_key_symmetric(const peacemakr_key_t *key);
EVP_PKEY *peacemakr_key_asymmetric(const peacemakr_key_t *key);

#endif // PEACEMAKR_CORE_CRYPTO_KEY_H
