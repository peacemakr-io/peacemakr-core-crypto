//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_SDK_CRYPTOBUFFER_HPP
#define PEACEMAKR_SDK_CRYPTOBUFFER_HPP

#include <cstddef>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <CryptoAllocator.hpp>

namespace peacemakr {

class CryptoContext;

class CryptoBuffer {

public:
  explicit CryptoBuffer(CryptoContext &ctx);

  CryptoBuffer(const CryptoBuffer &other);

  CryptoBuffer(CryptoBuffer &&other) noexcept;

  CryptoBuffer(CryptoContext &ctx, size_t size_bits);

  virtual ~CryptoBuffer() = default;

  void InitZero();

  void InitRandom();

  void Resize(size_t newsize);

  const unsigned char *Get() const;
  unsigned char *Get();
  size_t GetBufSize();

private:
  CryptoContext &m_ctx_;
  std::vector<unsigned char, CryptoAllocator<unsigned char>> m_buf_;
};

} // namespace peacemakr

#endif // PEACEMAKR_SDK_CRYPTOBUFFER_HPP
