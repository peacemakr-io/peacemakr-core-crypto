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

#include <stdlib.h>

#include "common-jni.h"
#include "crypto.h"
#include "random.h"

static bool setNativeKey(JNIEnv *env, jobject this, peacemakr_key_t *ptr) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");

  jlong current_key = (*env)->GetLongField(env, this, fieldID);
  if (current_key != 0) {
    return false;
  }

  (*env)->SetLongField(env, this, fieldID, (long)ptr);
  (*env)->DeleteLocalRef(env, clazz);
  return true;
}

static peacemakr_key_t *getNativeKey(JNIEnv *env, jobject this) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");
  (*env)->DeleteLocalRef(env, clazz);
  return (peacemakr_key_t *)(*env)->GetLongField(env, this, fieldID);
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newAsymmetric(
    JNIEnv *env, jobject this, jint asymm_cipher, jint symm_cipher,
    jlong rand) {
  peacemakr_key_t *asymm_key = peacemakr_key_new_asymmetric(
      asymm_cipher, symm_cipher, (random_device_t *)rand);

  if (!setNativeKey(env, this, asymm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newSymmetric(
    JNIEnv *env, jobject this, jint symm_cipher, jlong rand) {
  peacemakr_key_t *symm_key =
      peacemakr_key_new_symmetric(symm_cipher, (random_device_t *)rand);

  if (!setNativeKey(env, this, symm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromBytes(
    JNIEnv *env, jobject this, jint symm_cipher, jbyteArray bytes) {
  jbyte *raw = (*env)->GetByteArrayElements(env, bytes, NULL);
  const jsize length = (*env)->GetArrayLength(env, bytes);

  peacemakr_key_t *symm_key =
      peacemakr_key_new_bytes(symm_cipher, (uint8_t *)raw, length);
  if (!setNativeKey(env, this, symm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
  (*env)->ReleaseByteArrayElements(env, bytes, raw, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromPassword(
    JNIEnv *env, jobject this, jint symm_cipher, jint digest_algorithm,
    jstring password, jstring salt, jint iterations) {
  const jchar *raw_pass = (*env)->GetStringChars(env, password, NULL);
  const jsize pass_len = (*env)->GetStringLength(env, password);

  const jchar *raw_salt = (*env)->GetStringChars(env, salt, NULL);
  const jsize salt_len = (*env)->GetStringLength(env, salt);

  peacemakr_key_t *symm_key = peacemakr_key_new_from_password(
      symm_cipher, digest_algorithm, (uint8_t *)raw_pass, pass_len,
      (uint8_t *)raw_salt, salt_len, iterations);
  if (!setNativeKey(env, this, symm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
  (*env)->ReleaseStringChars(env, password, raw_pass);
  (*env)->ReleaseStringChars(env, salt, raw_salt);
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromMaster(
    JNIEnv *env, jobject this, jint symm_cipher, jint digest_algorithm,
    jlong master_key, jbyteArray bytes) {
  jbyte *raw = (*env)->GetByteArrayElements(env, bytes, NULL);
  const jsize length = (*env)->GetArrayLength(env, bytes);

  peacemakr_key_t *symm_key = peacemakr_key_new_from_master(
      symm_cipher, digest_algorithm, (const peacemakr_key_t *)master_key,
      (uint8_t *)raw, length);
  if (!setNativeKey(env, this, symm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }

  (*env)->ReleaseByteArrayElements(env, bytes, raw, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromPubPem(
    JNIEnv *env, jobject this, jint asymm_cipher, jint symm_cipher,
    jstring buf) {
  const jchar *raw_buf = (*env)->GetStringChars(env, buf, NULL);
  const jsize buf_len = (*env)->GetStringLength(env, buf);

  peacemakr_key_t *asymm_key = peacemakr_key_new_pem_pub(
      asymm_cipher, symm_cipher, (const char *)raw_buf, buf_len);
  if (!setNativeKey(env, this, asymm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
  (*env)->ReleaseStringChars(env, buf, raw_buf);
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromPrivPem(
    JNIEnv *env, jobject this, jint asymm_cipher, jint symm_cipher,
    jstring buf) {
  const jchar *raw_buf = (*env)->GetStringChars(env, buf, NULL);
  const jsize buf_len = (*env)->GetStringLength(env, buf);

  peacemakr_key_t *asymm_key = peacemakr_key_new_pem_priv(
      asymm_cipher, symm_cipher, (const char *)raw_buf, buf_len);
  if (!setNativeKey(env, this, asymm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
  (*env)->ReleaseStringChars(env, buf, raw_buf);
}

JNIEXPORT jlong JNICALL Java_io_peacemakr_corecrypto_Key_dhGenerate(
    JNIEnv *env, jobject this, jint symm_cipher, jlong peer_key) {
  peacemakr_key_t *symm_key = peacemakr_key_dh_generate(
      symm_cipher, getNativeKey(env, this), (const peacemakr_key_t *)peer_key);
  return (long)symm_key;
}

JNIEXPORT jint JNICALL Java_io_peacemakr_corecrypto_Key_getMode(JNIEnv *env,
                                                                jobject this) {
  return peacemakr_key_get_config(getNativeKey(env, this)).mode;
}

JNIEXPORT jint JNICALL
Java_io_peacemakr_corecrypto_Key_getSymmCipher(JNIEnv *env, jobject this) {
  return peacemakr_key_get_config(getNativeKey(env, this)).symm_cipher;
}

JNIEXPORT jint JNICALL
Java_io_peacemakr_corecrypto_Key_getAsymmCipher(JNIEnv *env, jobject this) {
  return peacemakr_key_get_config(getNativeKey(env, this)).asymm_cipher;
}

JNIEXPORT jint JNICALL
Java_io_peacemakr_corecrypto_Key_getDigestAlgorithm(JNIEnv *env, jobject this) {
  return peacemakr_key_get_config(getNativeKey(env, this)).digest_algorithm;
}

JNIEXPORT jstring JNICALL
Java_io_peacemakr_corecrypto_Key_toPrivPem(JNIEnv *env, jobject this) {

  char *pem_buf = NULL;
  size_t pem_buf_size = 0;
  bool success = peacemakr_key_priv_to_pem(getNativeKey(env, this), &pem_buf,
                                           &pem_buf_size);
  if (!success) {
    free(pem_buf);
    return false;
  }

  jstring out = (*env)->NewString(env, (jchar *)pem_buf, pem_buf_size);
  free(pem_buf);
  // TODO: should DeleteLocalRef on out?
  return out;
}

JNIEXPORT jstring JNICALL
Java_io_peacemakr_corecrypto_Key_toPubPem(JNIEnv *env, jobject this) {

  char *pem_buf = NULL;
  size_t pem_buf_size = 0;
  bool success = peacemakr_key_pub_to_pem(getNativeKey(env, this), &pem_buf,
                                          &pem_buf_size);
  if (!success) {
    free(pem_buf);
    return false;
  }

  jstring out = (*env)->NewString(env, (jchar *)pem_buf, pem_buf_size);
  free(pem_buf);
  // TODO: should DeleteLocalRef on out?
  return out;
}

JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Key_getBytes(JNIEnv *env, jobject this) {

  uint8_t *buf = NULL;
  size_t buf_size = 0;
  bool success =
      peacemakr_key_get_bytes(getNativeKey(env, this), &buf, &buf_size);
  if (!success) {
    free(buf);
    return false;
  }

  jbyteArray out = (*env)->NewByteArray(env, buf_size);
  (*env)->SetByteArrayRegion(env, out, 0, buf_size, (jbyte *)buf);
  free(buf);
  // TODO: should DeleteLocalRef on out?
  return out;
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_free(JNIEnv *env,
                                                             jobject this) {

  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");

  jlong current_key = (*env)->GetLongField(env, this, fieldID);
  if (current_key == 0) {
    return;
  }

  // Free the key
  peacemakr_key_free((peacemakr_key_t *)current_key);

  // And set the java field to 0
  (*env)->SetLongField(env, this, fieldID, 0);
  (*env)->DeleteLocalRef(env, this);
}

#ifdef __cplusplus
}
#endif
