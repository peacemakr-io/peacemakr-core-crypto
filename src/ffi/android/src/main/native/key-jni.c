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

#include <crypto.h>
#include <jni.h>
#include <random.h>

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

static bool setNativeKey(JNIEnv *env, jobject this, peacemakr_key_t *ptr) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");

  jlong current_key = (*env)->GetLongField(env, this, fieldID);
  if (current_key != 0) {
    return false;
  }

  (*env)->SetLongField(env, this, fieldID, (long)ptr);
  return true;
}

static peacemakr_key_t *getNativeKey(JNIEnv *env, jobject this) {
  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID fieldID = (*env)->GetFieldID(env, clazz, "nativeKey", "J");
  return (peacemakr_key_t *)(*env)->GetLongField(env, this, fieldID);
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newAsymmetric(
    JNIEnv *env, jobject this, jint asymm_cipher, jint symm_cipher,
    jlong rand) {
  peacemakr_key_t *asymmKey = peacemakr_key_new_asymmetric(
      asymm_cipher, symm_cipher, (random_device_t *)rand);

  if (!setNativeKey(env, this, asymmKey)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newSymmetric(
    JNIEnv *env, jobject this, jint symm_cipher, jlong rand) {
  peacemakr_key_t *symmKey =
      peacemakr_key_new_symmetric(symm_cipher, (random_device_t *)rand);
  if (!setNativeKey(env, this, symmKey)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromBytes(
    JNIEnv *env, jobject this, jint symm_cipher, jbyteArray bytes) {
  jbyte *raw = (*env)->GetByteArrayElements(env, bytes, NULL);
  const jsize length = (*env)->GetArrayLength(env, bytes);
  (*env)->ReleaseByteArrayElements(env, bytes, raw, JNI_ABORT);

  peacemakr_key_t *symmKey =
      peacemakr_key_new_bytes(symm_cipher, (uint8_t *)raw, length);
  if (!setNativeKey(env, this, symmKey)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromPassword(
    JNIEnv *env, jobject this, jint symm_cipher, jint digest_algorithm,
    jstring password, jstring salt, jint iterations) {
  const jchar *raw_pass = (*env)->GetStringChars(env, password, NULL);
  const jsize pass_len = (*env)->GetStringLength(env, password);
  (*env)->ReleaseStringChars(env, password, raw_pass);

  const jchar *raw_salt = (*env)->GetStringChars(env, salt, NULL);
  const jsize salt_len = (*env)->GetStringLength(env, salt);

  peacemakr_key_t *symmKey = peacemakr_key_new_from_password(
      symm_cipher, digest_algorithm, (uint8_t *)raw_pass, pass_len,
      (uint8_t *)raw_salt, salt_len, iterations);
  if (!setNativeKey(env, this, symmKey)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromMaster(
    JNIEnv *env, jobject this, jint symm_cipher, jint digest_algorithm,
    jlong master_key, jbyteArray bytes) {
  jbyte *raw = (*env)->GetByteArrayElements(env, bytes, NULL);
  const jsize length = (*env)->GetArrayLength(env, bytes);
  (*env)->ReleaseByteArrayElements(env, bytes, raw, JNI_ABORT);

  peacemakr_key_t *symmKey = peacemakr_key_new_from_master(
      symm_cipher, digest_algorithm, (const peacemakr_key_t *)master_key,
      (uint8_t *)raw, length);
  if (!setNativeKey(env, this, symmKey)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromPubPem(
    JNIEnv *env, jobject this, jint asymm_cipher, jint symm_cipher,
    jstring buf) {
  const jchar *raw_buf = (*env)->GetStringChars(env, buf, NULL);
  const jsize buf_len = (*env)->GetStringLength(env, buf);
  (*env)->ReleaseStringChars(env, buf, raw_buf);

  peacemakr_key_t *asymmKey = peacemakr_key_new_pem_pub(
      asymm_cipher, symm_cipher, (const char *)raw_buf, buf_len);
  if (!setNativeKey(env, this, asymmKey)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Key_newFromPrivPem(
    JNIEnv *env, jobject this, jint asymm_cipher, jint symm_cipher,
    jstring buf) {
  const jchar *raw_buf = (*env)->GetStringChars(env, buf, NULL);
  const jsize buf_len = (*env)->GetStringLength(env, buf);
  (*env)->ReleaseStringChars(env, buf, raw_buf);

  peacemakr_key_t *asymmKey = peacemakr_key_new_pem_priv(
      asymm_cipher, symm_cipher, (const char *)raw_buf, buf_len);
  if (!setNativeKey(env, this, asymmKey)) {
    LOGE("%s", "Attempting to reset a key\n");
  }
}

JNIEXPORT jlong JNICALL Java_io_peacemakr_corecrypto_Key_dhGenerate(
    JNIEnv *env, jobject this, jint symm_cipher, jlong peer_key) {
  peacemakr_key_t *symmKey = peacemakr_key_dh_generate(
      symm_cipher, getNativeKey(env, this), (const peacemakr_key_t *)peer_key);
  return (long)symmKey;
}

#ifdef __cplusplus
}
#endif
