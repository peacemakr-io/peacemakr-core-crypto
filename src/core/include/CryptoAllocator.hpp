//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CRYPTOALLOCATOR_HPP
#define PEACEMAKR_CORE_CRYPTO_CRYPTOALLOCATOR_HPP

#include <cstdint>
#include <cstdlib>
#include <new>

#include <openssl/crypto.h>

#include <glog/logging.h>

namespace peacemakr {

inline void SecureHeapInit(size_t size, int minsize) {
  if (1 != CRYPTO_secure_malloc_initialized()) // not initialized
    CRYPTO_secure_malloc_init(size, minsize);
}

inline void SecureHeapDone() {
  if (1 == CRYPTO_secure_malloc_initialized()) // already initialized
    CRYPTO_secure_malloc_done();
}

template <typename T> class CryptoAllocator {
public:
  typedef T value_type;
  CryptoAllocator() = default;
  template <class U>
  constexpr CryptoAllocator(const CryptoAllocator<U> &) noexcept {}

  T *allocate(size_t n) {
    if (n > OPENSSL_MALLOC_MAX_NELEMS(T)) {
      DLOG(FATAL) << "too many elements";
    }

    if (1 != CRYPTO_secure_malloc_initialized()) {
      DLOG(ERROR) << "secure malloc uninitialized";
    }

    T *ptr = static_cast<T *>(OPENSSL_secure_malloc(n));
    if (ptr == nullptr) {
      DLOG(FATAL) << "malloc returned nullptr";
    }

    return ptr;
  }
  void deallocate(T *p, size_t n) noexcept { OPENSSL_secure_clear_free(p, n); }
};
} // namespace peacemakr

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTOALLOCATOR_HPP
