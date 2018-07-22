//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "CryptoBuffer.hpp"

#include <string>

namespace peacemakr {
CryptoBuffer::CryptoBuffer(CryptoContext &ctx) : m_ctx_(ctx) {}

CryptoBuffer::CryptoBuffer(const CryptoBuffer &other)
    : m_ctx_(other.m_ctx_), m_buf_(other.m_buf_.begin(), other.m_buf_.end()) {}

CryptoBuffer::CryptoBuffer(CryptoBuffer &&other) noexcept
    : m_ctx_(other.m_ctx_), m_buf_(other.m_buf_.begin(), other.m_buf_.end()) {}

CryptoBuffer::CryptoBuffer(CryptoContext &ctx, size_t size_bits)
    : m_ctx_(ctx), m_buf_(size_bits / CHAR_BIT) {
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (urandom.is_open()) {
    if (!urandom.read((char *)m_buf_.data(), size_bits / CHAR_BIT)) {
      throw std::runtime_error("random buffer creation failed");
    }
    urandom.close();
  }
}

void CryptoBuffer::InitZero(size_t n) {
  m_buf_ =
      std::move(std::vector<unsigned char, CryptoAllocator<unsigned char>>(n));
}

void CryptoBuffer::Resize(size_t newsize) { m_buf_.resize(newsize); }

const unsigned char *CryptoBuffer::Get() const { return m_buf_.data(); }

unsigned char *CryptoBuffer::Get() { return m_buf_.data(); }

size_t CryptoBuffer::GetBufSize() { return m_buf_.size(); }

} // namespace peacemakr
