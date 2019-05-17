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

#include "random.h"
#include "common-jni.h"

// TODO: this is very hacky...there may be a nicer way to do it

typedef struct {
  jmethodID generateID;
  jmethodID errID;
  JNIEnv *env;
  jobject this;
} jni_random_device_t ;

static jni_random_device_t jni_random_device;

int jni_generate_rand(unsigned char *buf, size_t size) {
  jbyteArray bytes = (*jni_random_device.env)->NewByteArray(jni_random_device.env, size);

  jint result = (*jni_random_device.env)->CallIntMethod(jni_random_device.env, jni_random_device.this, jni_random_device.generateID, bytes);
  jbyte *rawData = (*jni_random_device.env)->GetByteArrayElements(jni_random_device.env, bytes, NULL);

  memcpy(buf, rawData, size);

  return result;
}

const char *jni_err(int code) {
  jstring result = (jstring)(*jni_random_device.env)->CallObjectMethod(jni_random_device.env, jni_random_device.this, jni_random_device.errID, code);
  const char *charResult = (*jni_random_device.env)->GetStringUTFChars(jni_random_device.env, result, NULL);
  const size_t charLen = (*jni_random_device.env)->GetStringLength(jni_random_device.env, result);

  char *outResult = calloc(charLen, sizeof(char));
  memcpy(outResult, charResult, charLen);

  (*jni_random_device.env)->ReleaseStringUTFChars(jni_random_device.env, result, charResult);

  return outResult;
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_RandomDevice_registerNative
        (JNIEnv *env, jobject this) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jni_random_device.generateID = (*env)->GetMethodID(env, clazz, "generate", "([B)I");
  jni_random_device.errID = (*env)->GetMethodID(env, clazz, "error", "(I)Ljava/lang/String;");
  jni_random_device.env = env;
  jni_random_device.this = this;

  random_device_t *rng = malloc(sizeof(random_device_t));
  rng->generator = (rng_buf)&jni_generate_rand;
  rng->err = (rng_err)&jni_err;

  jfieldID ptr = (*env)->GetFieldID(env, clazz, "nativePtr", "J");
  (*env)->SetLongField(env, this, ptr, (long)rng);
}

#ifdef __cplusplus
}
#endif
