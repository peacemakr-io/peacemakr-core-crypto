//
// Created by Aman LaChapelle on 2019-05-16.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
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


#ifndef PEACEMAKR_CORE_CRYPTO_COMMON_JNOI_H
#define PEACEMAKR_CORE_CRYPTO_COMMON_JNOI_H

#ifdef __ANDROID__
static const char *kTAG = "peacemakr-core-crypto";
#include <android/log.h>
// Android log function wrappers
#define LOGI(...)                                                              \
  ((void)__android_log_print(ANDROID_LOG_INFO, kTAG, __VA_ARGS__))
#define LOGW(...)                                                              \
  ((void)__android_log_print(ANDROID_LOG_WARN, kTAG, __VA_ARGS__))
#define LOGE(...)                                                              \
  ((void)__android_log_print(ANDROID_LOG_ERROR, kTAG, __VA_ARGS__))
#else // __ANDROID__
#define LOGI(...) ((void)printf(__VA_ARGS__))
#define LOGW(...) ((void)printf(__VA_ARGS__))
#define LOGE(...) ((void)printf(__VA_ARGS__))
#endif // __ANDROID__

static void log_callback(const char *msg) { LOGE("%s", msg); }

void setup_log_callback(void) __attribute__((constructor));
void setup_log_callback() { peacemakr_set_log_callback(&log_callback); }

#endif //PEACEMAKR_CORE_CRYPTO_COMMON_JNOI_H
