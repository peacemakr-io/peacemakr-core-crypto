//
// Created by Aman LaChapelle on 8/11/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
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


#ifndef PEACEMAKR_CORE_CRYPTO_KEY_H
#define PEACEMAKR_CORE_CRYPTO_KEY_H

#include <crypto.h>

#include <stddef.h>
#include <openssl/ossl_typ.h>


typedef struct PeacemakrKey peacemakr_key_t;

const uint8_t *PeacemakrKey_symmetric(peacemakr_key_t *key, size_t *keylen);
const EVP_PKEY *PeacemakrKey_asymmetric(peacemakr_key_t *key);

#endif //PEACEMAKR_CORE_CRYPTO_KEY_H
