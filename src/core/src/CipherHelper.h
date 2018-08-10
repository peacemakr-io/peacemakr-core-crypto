//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CIPHERHELPER_H
#define PEACEMAKR_CORE_CRYPTO_CIPHERHELPER_H

#include "Logging.h"
#include <crypto.h>
#include <openssl/evp.h>

inline const EVP_CIPHER *parse_cipher(crypto_config_t cfg) {

  switch (cfg.mode) {
  case SYMMETRIC: {
    switch (cfg.symm_cipher) {
    case AES_128_GCM:
      return EVP_aes_128_gcm();
    case AES_192_GCM:
      return EVP_aes_192_gcm();
    case AES_256_GCM:
      return EVP_aes_256_gcm();
    case AES_128_CBC:
      return EVP_aes_128_cbc();
    case AES_192_CBC:
      return EVP_aes_192_cbc();
    case AES_256_CBC:
      return EVP_aes_256_cbc();
    case AES_128_CFB:
      return EVP_aes_128_cfb();
    case AES_192_CFB:
      return EVP_aes_192_cfb();
    case AES_256_CFB:
      return EVP_aes_256_cfb();
    case AES_128_ECB:
      return EVP_aes_128_ecb();
    case AES_192_ECB:
      return EVP_aes_192_ecb();
    case AES_256_ECB:
      return EVP_aes_256_ecb();
    case AES_128_OFB:
      return EVP_aes_128_ofb();
    case AES_192_OFB:
      return EVP_aes_192_ofb();
    case AES_256_OFB:
      return EVP_aes_256_ofb();
    case AES_128_CTR:
      return EVP_aes_128_ctr();
    case AES_192_CTR:
      return EVP_aes_192_ctr();
    case AES_256_CTR:
      return EVP_aes_256_ctr();
    case AES_128_CCM:
      return EVP_aes_128_ccm();
    case AES_192_CCM:
      return EVP_aes_192_ccm();
    case AES_256_CCM:
      return EVP_aes_256_ccm();
    case AES_128_WRAP:
      return EVP_aes_128_wrap();
    case AES_192_WRAP:
      return EVP_aes_192_wrap();
    case AES_256_WRAP:
      return EVP_aes_256_wrap();
    case AES_128_WRAP_PAD:
      return EVP_aes_128_wrap_pad();
    case AES_192_WRAP_PAD:
      return EVP_aes_192_wrap_pad();
    case AES_256_WRAP_PAD:
      return EVP_aes_256_wrap_pad();
    case AES_128_XTS:
      return EVP_aes_128_xts();
    case AES_256_XTS:
      return EVP_aes_256_xts();
    case AES_128_CBC_HMAC_SHA1:
      return EVP_aes_256_cbc_hmac_sha1();
    case AES_256_CBC_HMAC_SHA1:
      return EVP_aes_256_cbc_hmac_sha1();
    case AES_128_CBC_HMAC_SHA256:
      return EVP_aes_256_cbc_hmac_sha256();
    case AES_256_CBC_HMAC_SHA256:
      return EVP_aes_256_cbc_hmac_sha256();
    case CHACHA20:
      return EVP_chacha20();
    case CHACHA20_POLY1305:
      return EVP_chacha20_poly1305();
    }
  }
  case ASYMMETRIC: {
    PEACEMAKR_WARNING("no EVP_CIPHER for asymmetric cipher");
    break;
  }
  }

  return NULL;
}

#endif // PEACEMAKR_CORE_CRYPTO_CIPHERHELPER_H
