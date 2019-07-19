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

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Plaintext_fromNative(
    JNIEnv *env, jobject this, jlong ptr) {

  plaintext_t *plaintext = (plaintext_t *)ptr;

  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID dataID = (*env)->GetFieldID(env, clazz, "data", "[B");
  jfieldID aadID = (*env)->GetFieldID(env, clazz, "aad", "[B");

  jbyteArray dataField = (jbyteArray)(*env)->GetObjectField(env, this, dataID);
  (*env)->SetByteArrayRegion(env, dataField, 0, plaintext->data_len,
                             (jbyte *)plaintext->data);

  jbyteArray aadField = (jbyteArray)(*env)->GetObjectField(env, this, aadID);
  (*env)->SetByteArrayRegion(env, aadField, 0, plaintext->aad_len,
                             (jbyte *)plaintext->aad);

  free((void *)plaintext->data);
  free((void *)plaintext->aad);
  free((void *)plaintext);
  (*env)->DeleteLocalRef(env, dataField);
  (*env)->DeleteLocalRef(env, aadField);
  (*env)->DeleteLocalRef(env, clazz);
}

JNIEXPORT jlong JNICALL
Java_io_peacemakr_corecrypto_Plaintext_toNative(JNIEnv *env, jobject this) {

  jclass clazz = (*env)->GetObjectClass(env, this);
  jfieldID dataID = (*env)->GetFieldID(env, clazz, "data", "[B");
  jfieldID aadID = (*env)->GetFieldID(env, clazz, "aad", "[B");

  jbyteArray dataField = (jbyteArray)(*env)->GetObjectField(env, this, dataID);
  jbyte *rawData = (*env)->GetByteArrayElements(env, dataField, NULL);
  const jsize dataLen = (*env)->GetArrayLength(env, dataField);

  jbyteArray aadField = (jbyteArray)(*env)->GetObjectField(env, this, aadID);
  jbyte *rawAAD = (*env)->GetByteArrayElements(env, aadField, NULL);
  const jsize aadLen = (*env)->GetArrayLength(env, aadField);

  plaintext_t *out = malloc(sizeof(plaintext_t));
  if (out == NULL) {
    LOGE("Failed to malloc space for a plaintext object");
    return 0;
  }
  out->data = calloc(dataLen, sizeof(uint8_t));
  if (out->data == NULL) {
    LOGE("Failed to malloc space for a plaintext object's data");
  }
  out->data_len = dataLen;
  out->aad = calloc(aadLen, sizeof(uint8_t));
  if (out->aad == NULL) {
    LOGE("Failed to malloc space for a plaintext object's aad");
  }
  out->aad_len = aadLen;

  memcpy((void *)out->data, rawData, dataLen);
  memcpy((void *)out->aad, rawAAD, aadLen);

  (*env)->ReleaseByteArrayElements(env, dataField, rawData, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, aadField, rawAAD, JNI_ABORT);

  (*env)->DeleteLocalRef(env, dataField);
  (*env)->DeleteLocalRef(env, aadField);
  (*env)->DeleteLocalRef(env, clazz);

  return (long)out;
}

#ifdef __cplusplus
}
#endif
