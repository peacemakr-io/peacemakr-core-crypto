//
// Created by Aman LaChapelle on 2019-05-12.
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

#ifdef __cplusplus
extern "C" {
#endif

#include <jni.h>
#include <android/log.h>
#include <crypto.h>
#include <random.h>

// Android log function wrappers
static const char* kTAG = "peacemakr-core-crypto";
#define LOGI(...) \
  ((void)__android_log_print(ANDROID_LOG_INFO, kTAG, __VA_ARGS__))
#define LOGW(...) \
  ((void)__android_log_print(ANDROID_LOG_WARN, kTAG, __VA_ARGS__))
#define LOGE(...) \
  ((void)__android_log_print(ANDROID_LOG_ERROR, kTAG, __VA_ARGS__))

static void log_callback(const char *msg) {
    LOGI("%s", msg);
}

void setup_log_callback(void) __attribute__((constructor));
void setup_log_callback() {
    peacemakr_set_log_callback(&log_callback);
}


JNIEXPORT jlong JNICALL Java_io_peacemakr_corecrypto_Key_peacemakr_1key_1new_1asymmetric
        (JNIEnv *env, jobject this, jint asymm_cipher, jint symm_cipher, jlong rand) {
  peacemakr_key_t *asymmKey = peacemakr_key_new_asymmetric(asymm_cipher, symm_cipher, (random_device_t *)rand);
  return (long)asymmKey;
}

#ifdef __cplusplus
}
#endif
