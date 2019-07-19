//
// Created by Aman LaChapelle on 2019-05-16.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//


#ifndef PEACEMAKR_CORE_CRYPTO_COMMON_JNOI_H
#define PEACEMAKR_CORE_CRYPTO_COMMON_JNOI_H
#ifdef __cplusplus
extern "C" {
#endif

#include <jni.h>

#include <stdlib.h>

#include "crypto.h"

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

uint32_t unwrapEnumToInt(JNIEnv *env, jobject asymm_cipher, const char *class);

jobject constructObject(JNIEnv *env, jclass clazz);

bool setNativeKey(JNIEnv *env, jobject this, peacemakr_key_t *ptr);

void clearNativeKey(JNIEnv *env, jobject this);

peacemakr_key_t *getNativeKey(JNIEnv *env, jobject this);

#ifdef __cplusplus
}
#endif
#endif //PEACEMAKR_CORE_CRYPTO_COMMON_JNOI_H
