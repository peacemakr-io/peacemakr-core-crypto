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

#ifndef PEACEMAKR_CORE_CRYPTO_EVPHELPER_H
#define PEACEMAKR_CORE_CRYPTO_EVPHELPER_H

#include "crypto.h"

#include <openssl/evp.h>

static inline const EVP_CIPHER *parse_cipher(symmetric_cipher cfg) {

  switch (cfg) {
  case AES_128_GCM:
    return EVP_aes_128_gcm();
  case AES_192_GCM:
    return EVP_aes_192_gcm();
  case AES_256_GCM:
    return EVP_aes_256_gcm();
  case CHACHA20_POLY1305:
    return EVP_chacha20_poly1305();
  }

  return NULL;
}

static inline size_t get_taglen(symmetric_cipher cfg) {
  switch (cfg) {
  case AES_128_GCM:
    return 16;
  case AES_192_GCM:
    return 16;
  case AES_256_GCM:
    return 16;
  case CHACHA20_POLY1305:
    return 16;
  }
  return 0;
}

static inline const EVP_MD *parse_digest(message_digest_algorithm cfg) {
  switch (cfg) {
  case SHA_224:
    return EVP_sha224();
  case SHA_256:
    return EVP_sha256();
  case SHA_384:
    return EVP_sha384();
  case SHA_512:
    return EVP_sha512();
  case SHA3_224:
    return EVP_sha3_224();
  case SHA3_256:
    return EVP_sha3_256();
  case SHA3_384:
    return EVP_sha3_384();
  case SHA3_512:
    return EVP_sha3_512();
  }
  return NULL;
}

static inline size_t get_digest_len(message_digest_algorithm cfg) {
  switch (cfg) {
  case SHA_224:
    return (size_t)EVP_MD_size(EVP_sha224());
  case SHA_256:
    return (size_t)EVP_MD_size(EVP_sha256());
  case SHA_384:
    return (size_t)EVP_MD_size(EVP_sha384());
  case SHA_512:
    return (size_t)EVP_MD_size(EVP_sha512());
  case SHA3_224:
    return (size_t)EVP_MD_size(EVP_sha3_224());
  case SHA3_256:
    return (size_t)EVP_MD_size(EVP_sha3_256());
  case SHA3_384:
    return (size_t)EVP_MD_size(EVP_sha3_384());
  case SHA3_512:
    return (size_t)EVP_MD_size(EVP_sha3_512());
  }
  return 0;
}

#endif // PEACEMAKR_CORE_CRYPTO_EVPHELPER_H
