//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_SDK_CRYPTOCONFIG_HPP
#define PEACEMAKR_SDK_CRYPTOCONFIG_HPP

#include <CryptoBuffer.hpp>
#include <cstdint>
#include <openssl/evp.h>

namespace peacemakr {

typedef EVP_CIPHER *(*CipherMode)();

class CryptoConfig {
public:
  virtual ~CryptoConfig() = default;

  virtual CipherMode GetCipherMode() const = 0;
  virtual uint16_t GetIVLen() const = 0;
  virtual size_t CalculateCiphertextLen(size_t message_len) = 0;

  // Serialize config somehow
};
} // namespace peacemakr

#endif // PEACEMAKR_SDK_CRYPTOCONFIG_HPP
