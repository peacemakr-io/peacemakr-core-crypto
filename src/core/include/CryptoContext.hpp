//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr-core-crypto
// Copyright (c) 2018 peacemakr
// Full license at peacemakr-core-crypto/LICENSE.txt
//

#ifndef PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_HPP
#define PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_HPP

#include <cstddef>

namespace peacemakr {
class CryptoContext {
public:
  explicit CryptoContext(size_t secure_heap_size,
                         int min_obj_size = sizeof(char));
  ~CryptoContext();
};
} // namespace peacemakr

#endif // PEACEMAKR_CORE_CRYPTO_CRYPTOCONTEXT_HPP
