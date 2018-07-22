//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#include "CryptoBuffer.hpp"

#include <fstream>
#include <iostream>
#include <string>

namespace peacemakr {
CryptoBuffer::CryptoBuffer(CryptoContext &ctx) : m_ctx_(ctx) {}

CryptoBuffer::CryptoBuffer(const CryptoBuffer &other)
    : m_ctx_(other.m_ctx_), m_buf_(other.m_buf_.begin(), other.m_buf_.end()) {}

CryptoBuffer::CryptoBuffer(CryptoBuffer &&other) noexcept
    : m_ctx_(other.m_ctx_), m_buf_(other.m_buf_.begin(), other.m_buf_.end()) {}

CryptoBuffer::CryptoBuffer(CryptoContext &ctx, size_t size_bytes)
    : m_ctx_(ctx), m_buf_(size_bytes) {}

void CryptoBuffer::InitZero() { std::fill(m_buf_.begin(), m_buf_.end(), 0); }

void CryptoBuffer::InitRandom(RandomDevice &rng) {
  if (!rng.FillRandom(m_buf_.data(), m_buf_.size())) {
    throw std::runtime_error("rng failed, " + rng.GetLastError());
  }
}

void CryptoBuffer::Resize(size_t newsize) { m_buf_.resize(newsize); }

const unsigned char *CryptoBuffer::Get() const { return m_buf_.data(); }

unsigned char *CryptoBuffer::Get() { return m_buf_.data(); }

size_t CryptoBuffer::GetBufSize() { return m_buf_.size(); }

} // namespace peacemakr
