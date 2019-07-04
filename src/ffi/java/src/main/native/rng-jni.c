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

#ifdef __cplusplus
extern "C" {
#endif

#include <jni.h>

#include <stdlib.h>
#include <string.h>

#include "common-jni.h"
#include "random.h"

static random_device_t jni_rng;

JNIEXPORT jlong JNICALL Java_io_peacemakr_corecrypto_RandomDevice_getNativePtr(
    JNIEnv *env, jobject this) {
  return (long)&jni_rng;
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_RandomDevice_registerNative(
    JNIEnv *env, jobject this) {
  jni_rng = get_default_random_device();
}

#ifdef __cplusplus
}
#endif
