//
// Created by Aman LaChapelle on 8/11/18.
//
// peacemakr_core_crypto
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_EVPHELPER_H
#define PEACEMAKR_CORE_CRYPTO_EVPHELPER_H

#include "peacemakr/crypto.h"

#include <openssl/evp.h>

static inline const EVP_CIPHER *parse_cipher(symmetric_cipher cfg) {

  switch (cfg) {
  case SYMMETRIC_UNSPECIFIED:
    return NULL;
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
  case SYMMETRIC_UNSPECIFIED:
    return 0;
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
  case DIGEST_UNSPECIFIED:
    return NULL;
  case SHA_224:
    return EVP_sha224();
  case SHA_256:
    return EVP_sha256();
  case SHA_384:
    return EVP_sha384();
  case SHA_512:
    return EVP_sha512();
  }
  return NULL;
}

static inline size_t get_digest_len(message_digest_algorithm cfg) {
  switch (cfg) {
  case DIGEST_UNSPECIFIED:
    return 0;
  case SHA_224:
    return (size_t)EVP_MD_size(EVP_sha224());
  case SHA_256:
    return (size_t)EVP_MD_size(EVP_sha256());
  case SHA_384:
    return (size_t)EVP_MD_size(EVP_sha384());
  case SHA_512:
    return (size_t)EVP_MD_size(EVP_sha512());
  }
  return 0;
}

#endif // PEACEMAKR_CORE_CRYPTO_EVPHELPER_H
