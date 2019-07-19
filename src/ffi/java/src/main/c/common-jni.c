//
// Created by Aman LaChapelle on 2019-07-18.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#ifdef __cplusplus
extern "C" {
#endif

#include "common-jni.h"

uint32_t unwrapEnumToInt(JNIEnv *env, jobject asymm_cipher, const char *class) {
  jmethodID getOrdinalValue =
      (*env)->GetMethodID(env, (*env)->FindClass(env, class), "ordinal", "()I");
  jint value = (*env)->CallIntMethod(env, asymm_cipher, getOrdinalValue);
  if (value < 0) {
    LOGE("Invalid value for %s: %d", class, value);
    return 0; // maps to ASYMMETRIC_UNSPECIFIED and SYMMETRIC_UNSPECIFIED
  }

  return value;
}

jobject constructObject(JNIEnv *env, jclass clazz) {
  jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "()V");
  return (*env)->NewObject(env, clazz, constructor);
}

bool setNativeKey(JNIEnv *env, jobject this, peacemakr_key_t *ptr) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");

  jlong current_key = (*env)->GetLongField(env, this, fieldID);
  if (current_key != 0) {
    return false;
  }

  (*env)->SetLongField(env, this, fieldID, (long)ptr);
  return true;
}

void clearNativeKey(JNIEnv *env, jobject this) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");

  (*env)->SetLongField(env, this, fieldID, 0);
}

peacemakr_key_t *getNativeKey(JNIEnv *env, jobject this) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");
  return (peacemakr_key_t *)(*env)->GetLongField(env, this, fieldID);
}

#ifdef __cplusplus
}
#endif