//
// Created by Aman LaChapelle on 2019-05-12.
//
// peacemakr_core_crypto
// Copyright (c) 2019 Aman LaChapelle
// Full license at peacemakr_core_crypto/LICENSE.txt
//

#ifdef __cplusplus
extern "C" {
#endif

#include <jni.h>

#include <stdlib.h>
#include <string.h>

#include "common-jni.h"
#include "crypto.h"
#include "random.h"

JNIEXPORT jobject JNICALL Java_io_peacemakr_corecrypto_AsymmetricKey_fromPRNG(
    JNIEnv *env, jclass clazz, jobject asymm_cipher, jobject symm_cipher) {
  random_device_t rand = get_default_random_device();

  peacemakr_key_t *asymm_key = peacemakr_key_new_asymmetric(
      unwrapEnumToInt(env, asymm_cipher,
                      "io/peacemakr/corecrypto/AsymmetricCipher"),
      unwrapEnumToInt(env, symm_cipher,
                      "io/peacemakr/corecrypto/SymmetricCipher"),
      &rand);

  jobject out = constructObject(env, clazz);

  if (!setNativeKey(env, out, asymm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }

  return out;
}

JNIEXPORT jobject JNICALL Java_io_peacemakr_corecrypto_AsymmetricKey_fromPubPem(
    JNIEnv *env, jclass clazz, jobject symm_cipher, jstring pub_pem) {

  const char *raw_buf = (*env)->GetStringUTFChars(env, pub_pem, NULL);
  const jsize buf_len = (*env)->GetStringLength(env, pub_pem);

  peacemakr_key_t *asymm_key = peacemakr_key_new_pem_pub(
      unwrapEnumToInt(env, symm_cipher,
                      "io/peacemakr/corecrypto/SymmetricCipher"),
      raw_buf, buf_len);

  // Clean up
  (*env)->ReleaseStringUTFChars(env, pub_pem, raw_buf);

  jobject out = constructObject(env, clazz);
  if (!setNativeKey(env, out, asymm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }

  return out;
}

JNIEXPORT jobject JNICALL
Java_io_peacemakr_corecrypto_AsymmetricKey_fromPrivPem(JNIEnv *env,
                                                       jclass clazz,
                                                       jobject symm_cipher,
                                                       jstring priv_pem) {
  const char *raw_buf = (*env)->GetStringUTFChars(env, priv_pem, NULL);
  const jsize buf_len = (*env)->GetStringLength(env, priv_pem);

  peacemakr_key_t *asymm_key = peacemakr_key_new_pem_priv(
      unwrapEnumToInt(env, symm_cipher,
                      "io/peacemakr/corecrypto/SymmetricCipher"),
      raw_buf, buf_len);

  // Clean up
  (*env)->ReleaseStringUTFChars(env, priv_pem, raw_buf);

  jobject out = constructObject(env, clazz);
  if (!setNativeKey(env, out, asymm_key)) {
    LOGE("%s", "Attempting to reset a key\n");
  }

  return out;
}

JNIEXPORT jstring JNICALL
Java_io_peacemakr_corecrypto_AsymmetricKey_getPubPemStr(JNIEnv *env,
                                                        jobject this) {
  peacemakr_key_t *native_key = getNativeKey(env, this);

  char *pub_pem;
  size_t pub_pem_len;
  peacemakr_key_pub_to_pem(native_key, &pub_pem, &pub_pem_len);

  if (pub_pem_len <= 0) {
    LOGE("%s\n", "Problem with exporting the public key to pem");
  }

  // Gotta copy over the string so we get it null-terminated
  char *out_str = calloc(pub_pem_len + 1, sizeof(char));
  memcpy(out_str, pub_pem, pub_pem_len);
  free(pub_pem);

  jstring out = (*env)->NewStringUTF(env, out_str);
  free(out_str);
  return out;
}

JNIEXPORT jstring JNICALL
Java_io_peacemakr_corecrypto_AsymmetricKey_getPrivPemStr(JNIEnv *env,
                                                         jobject this) {
  peacemakr_key_t *native_key = getNativeKey(env, this);

  char *priv_pem;
  size_t priv_pem_len = 0;
  peacemakr_key_priv_to_pem(native_key, &priv_pem, &priv_pem_len);

  if (priv_pem_len <= 0) {
    LOGE("%s\n", "Problem with exporting the private key to pem");
  }

  // Gotta copy over the string so we get it null-terminated
  char *out_str = calloc(priv_pem_len + 1, sizeof(char));
  memcpy(out_str, priv_pem, priv_pem_len);
  free(priv_pem);

  jstring out = (*env)->NewStringUTF(env, out_str);
  free(out_str);
  return out;
}

JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_AsymmetricKey_ecdhKeygen(JNIEnv *env, jobject this,
                                                      jobject symm_cipher,
                                                      jobject peer_key) {
  peacemakr_key_t *symm_key = peacemakr_key_dh_generate(
      unwrapEnumToInt(env, symm_cipher,
                      "io/peacemakr/corecrypto/SymmetricCipher"),
      getNativeKey(env, this), getNativeKey(env, peer_key));

  uint8_t *buf;
  size_t buf_len = 0;
  peacemakr_key_get_bytes(symm_key, &buf, &buf_len);

  jbyteArray out = (*env)->NewByteArray(env, buf_len);

  (*env)->SetByteArrayRegion(env, out, 0, buf_len, (jbyte *)buf);

  free(buf);
  return out;
}

JNIEXPORT void JNICALL
Java_io_peacemakr_corecrypto_AsymmetricKey_cleanup(JNIEnv *env, jobject this) {
  peacemakr_key_free(getNativeKey(env, this));
  clearNativeKey(env, this);
}

#ifdef __cplusplus
}
#endif
