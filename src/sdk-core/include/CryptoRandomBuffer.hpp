//
// Created by Aman LaChapelle on 7/20/18.
//
// peacemakr_sdk
// Copyright (c) 2018 Aman LaChapelle
// Full license at peacemakr_sdk/LICENSE.txt
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


#ifndef PEACEMAKR_SDK_CRYPTORAND_HPP
#define PEACEMAKR_SDK_CRYPTORAND_HPP

#include <cstddef>
#include <string>

namespace peacemakr {
  class CryptoRandomBuffer {
  public:
    explicit CryptoRandomBuffer(size_t size);

    explicit operator const char *();

  private:
    std::string m_buf_;
  };
}


#endif //PEACEMAKR_SDK_CRYPTORAND_HPP
