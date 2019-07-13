//
// Created by Aman LaChapelle on 2019-05-19.
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

#include <jni.h>

#include "crypto.h"

#include "common-jni.h"

void log_callback(const char *msg) { LOGE("%s", msg); }

JNIEXPORT void JNICALL
Java_io_peacemakr_corecrypto_CryptoContext_init(JNIEnv *env, jclass clazz) {
  peacemakr_set_log_callback(&log_callback);
  if (!peacemakr_init()) {
    // TODO: throw an error
    return;
  }
}

JNIEXPORT void JNICALL
Java_io_peacemakr_corecrypto_CryptoContext_ciphertextBlobFree(JNIEnv *env,
                                                              jclass clazz,
                                                              jlong blobAddr) {
  ciphertext_blob_free((ciphertext_blob_t *)blobAddr);
}

JNIEXPORT jlong JNICALL Java_io_peacemakr_corecrypto_CryptoContext_encrypt(
    JNIEnv *env, jclass clazz, jlong recipientKey, jlong plaintext,
    jlong rand) {
  return (long)peacemakr_encrypt((const peacemakr_key_t *)recipientKey,
                                 (const plaintext_t *)plaintext,
                                 (random_device_t *)rand);
}

JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_CryptoContext_sign(
    JNIEnv *env, jclass clazz, jlong senderKey, jlong plaintext, jint digest,
    jlong ciphertextBlob) {
  peacemakr_sign(
      (const peacemakr_key_t *)senderKey, (const plaintext_t *)plaintext,
      (message_digest_algorithm)digest, (ciphertext_blob_t *)ciphertextBlob);
}

JNIEXPORT jint JNICALL Java_io_peacemakr_corecrypto_CryptoContext_decrypt(
    JNIEnv *env, jclass clazz, jlong recipientKey, jlong ciphertextBlob,
    jlong plaintext) {
  return peacemakr_decrypt((const peacemakr_key_t *)recipientKey,
                           (ciphertext_blob_t *)ciphertextBlob,
                           (plaintext_t *)plaintext);
}

JNIEXPORT jboolean JNICALL
Java_io_peacemakr_corecrypto_CryptoContext_getUnverifiedAAD(
    JNIEnv *env, jclass clazz, jlong ciphertextBlob, jlong plaintext) {
  return peacemakr_get_unverified_aad((const ciphertext_blob_t *)ciphertextBlob,
                                      (plaintext_t *)plaintext);
}

JNIEXPORT jboolean JNICALL Java_io_peacemakr_corecrypto_CryptoContext_verify(
    JNIEnv *env, jclass clazz, jlong senderKey, jlong plaintext,
    jlong ciphertextBlob) {
  return peacemakr_verify((const peacemakr_key_t *)senderKey,
                          (const plaintext_t *)plaintext,
                          (ciphertext_blob_t *)ciphertextBlob);
}

JNIEXPORT jbyteArray JNICALL Java_io_peacemakr_corecrypto_CryptoContext_hmac(
    JNIEnv *env, jclass clazz, jint digest, jlong masterKey, jbyteArray buf) {
  // TODO
  return NULL;
}

JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_CryptoContext_serialize(JNIEnv *env, jclass clazz,
                                                     jint digest,
                                                     jlong ciphertextBlob) {
  // TODO
  return NULL;
}
JNIEXPORT jlong JNICALL Java_io_peacemakr_corecrypto_CryptoContext_deserialize(
    JNIEnv *env, jclass clazz, jbyteArray serialized) {
  // TODO
  return 0;
}
