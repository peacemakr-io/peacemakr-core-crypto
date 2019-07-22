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

#include "common-jni.h"
#include "crypto.h"
#include "random.h"

JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_encryptSymmetric(
    JNIEnv *env, jclass clazz, jbyteArray key, jobject symm_cipher,
    jobject sign_key, jbyteArray plaintext, jbyteArray aad, jobject digest) {

  jbyte *raw_key = (*env)->GetByteArrayElements(env, key, NULL);
  const jsize keylen = (*env)->GetArrayLength(env, key);

  // Construct a new key from the bytes and the symmetric cipher
  peacemakr_key_t *native_key = peacemakr_key_new_bytes(
      unwrapEnumToInt(env, symm_cipher,
                      "io/peacemakr/corecrypto/SymmetricCipher"),
      (const uint8_t *)raw_key, keylen);
  if (native_key == NULL) {
    LOGE("%s\n", "Error creating symmetric key");
    return NULL;
  }

  peacemakr_key_t *sign_native_key = NULL;
  if (sign_key != NULL) {
    sign_native_key = getNativeKey(env, sign_key);
    if (sign_native_key == NULL) {
      LOGE("%s\n", "Error creating signing key");
      return NULL;
    }
  }

  // now do the encrypt
  jbyte *raw_data = (*env)->GetByteArrayElements(env, plaintext, NULL);
  const jsize data_len = (*env)->GetArrayLength(env, plaintext);

  jbyte *rawAAD = (*env)->GetByteArrayElements(env, aad, NULL);
  const jsize aad_len = (*env)->GetArrayLength(env, aad);

  plaintext_t plain = {.data = (const uint8_t *)raw_data,
                       .data_len = data_len,
                       .aad = (const uint8_t *)rawAAD,
                       .aad_len = aad_len};

  random_device_t rand = get_default_random_device();

  ciphertext_blob_t *encrypted = peacemakr_encrypt(native_key, &plain, &rand);
  if (encrypted == NULL) {
    LOGE("%s\n", "Error encrypting message");
    peacemakr_key_free(native_key);
    return NULL;
  }

  message_digest_algorithm digest_algo =
      unwrapEnumToInt(env, digest, "io/peacemakr/corecrypto/MessageDigest");

  if (sign_native_key != NULL) {
    peacemakr_sign(sign_native_key, &plain, digest_algo, encrypted);
  }

  size_t out_len = 0;
  uint8_t *serialized = peacemakr_serialize(digest_algo, encrypted, &out_len);

  jbyteArray out = (*env)->NewByteArray(env, out_len);
  (*env)->SetByteArrayRegion(env, out, 0, out_len, (const jbyte *)serialized);

  // clean up
  (*env)->ReleaseByteArrayElements(env, plaintext, raw_data, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, aad, rawAAD, JNI_ABORT);
  peacemakr_key_free(native_key);
  free(serialized);

  return out;
}

JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_getCiphertextAAD(JNIEnv *env, jclass clazz,
                                                     jbyteArray ciphertext) {
  jbyte *raw_data = (*env)->GetByteArrayElements(env, ciphertext, NULL);
  const jsize data_len = (*env)->GetArrayLength(env, ciphertext);

  crypto_config_t cfg;
  ciphertext_blob_t *deserialized =
      peacemakr_deserialize((uint8_t *)raw_data, data_len, &cfg);
  if (deserialized == NULL) {
    LOGE("%s\n", "Deserialization of the message failed");
    return NULL;
  }

  plaintext_t plain;
  peacemakr_get_unverified_aad(deserialized, &plain);

  jbyteArray out = (*env)->NewByteArray(env, plain.aad_len);
  (*env)->SetByteArrayRegion(env, out, 0, plain.aad_len,
                             (const jbyte *)plain.aad);

  // Don't release the ciphertext byte array elements in case we need them later
  // for a decrypt operation
  free((void *)plain.data);
  free((void *)plain.aad);

  return out;
}

JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_decryptSymmetric(JNIEnv *env, jclass clazz,
                                                     jbyteArray key,
                                                     jobject verify_key,
                                                     jbyteArray ciphertext) {
  jbyte *raw_key = (*env)->GetByteArrayElements(env, key, NULL);
  const jsize keylen = (*env)->GetArrayLength(env, key);

  peacemakr_key_t *native_key = peacemakr_key_new_bytes(
      SYMMETRIC_UNSPECIFIED, (const uint8_t *)raw_key, keylen);
  if (native_key == NULL) {
    LOGE("%s\n", "Error creating symmetric key");
    return NULL;
  }

  peacemakr_key_t *verify_native_key = getNativeKey(env, verify_key);
  if (verify_native_key == NULL) {
    LOGE("%s\n", "Error creating verification key");
    peacemakr_key_free(native_key);
    return NULL;
  }

  jbyte *raw_data = (*env)->GetByteArrayElements(env, ciphertext, NULL);
  const jsize data_len = (*env)->GetArrayLength(env, ciphertext);

  crypto_config_t cfg;
  ciphertext_blob_t *deserialized =
      peacemakr_deserialize((uint8_t *)raw_data, data_len, &cfg);
  if (deserialized == NULL) {
    LOGE("%s\n", "Deserialization of the message failed");
    peacemakr_key_free(native_key);
    return NULL;
  }

  plaintext_t plaintext;
  decrypt_code did_succeed =
      peacemakr_decrypt(native_key, deserialized, &plaintext);
  if (did_succeed == DECRYPT_NEED_VERIFY) {
    if (!peacemakr_verify(verify_native_key, &plaintext, deserialized)) {
      LOGE("%s\n", "Verification of the message failed");
      peacemakr_key_free(native_key);
      return NULL;
    }
  }

  if (did_succeed == DECRYPT_FAILED) {
    LOGE("%s\n", "Decryption of the message failed");
    peacemakr_key_free(native_key);
    return NULL;
  }

  // We only want to release the byte array elements once we've successfully
  // decrypted the message
  (*env)->ReleaseByteArrayElements(env, ciphertext, raw_data, JNI_ABORT);

  // clean up the key, don't free the asymmetric key yet
  peacemakr_key_free(native_key);

  // re-pack the plaintext
  jbyteArray out = (*env)->NewByteArray(env, plaintext.data_len);
  (*env)->SetByteArrayRegion(env, out, 0, plaintext.data_len,
                             (const jbyte *)plaintext.data);

  // Clean up the C plaintext
  free((void *)plaintext.data);
  free((void *)plaintext.aad);

  return out;
}

JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_decryptAsymmetric(JNIEnv *env, jclass clazz,
                                                      jobject key,
                                                      jobject verify_key,
                                                      jbyteArray ciphertext) {

  peacemakr_key_t *native_key = getNativeKey(env, key);
  crypto_config_t native_key_config = peacemakr_key_get_config(native_key);
  if (native_key_config.asymm_cipher != RSA_2048 &&
      native_key_config.asymm_cipher != RSA_4096) {
    LOGE("%s\n", "Cannot call decryptAsymmetric with non-RSA key. For EC keys "
                 "call ecdhKeygen to create the symmetric encryption key and "
                 "use the symmetric functions.");
    peacemakr_key_free(native_key);
    return NULL;
  }

  peacemakr_key_t *verify_native_key = getNativeKey(env, verify_key);
  if (verify_native_key == NULL) {
    LOGE("%s\n", "Error creating verification key");
    peacemakr_key_free(native_key);
    return NULL;
  }

  jbyte *raw_data = (*env)->GetByteArrayElements(env, ciphertext, NULL);
  const jsize data_len = (*env)->GetArrayLength(env, ciphertext);

  crypto_config_t cfg;
  ciphertext_blob_t *deserialized =
      peacemakr_deserialize((uint8_t *)raw_data, data_len, &cfg);
  if (deserialized == NULL) {
    LOGE("%s\n", "Deserialization of the message failed");
    peacemakr_key_free(native_key);
    return NULL;
  }

  plaintext_t plaintext;
  decrypt_code did_succeed =
      peacemakr_decrypt(native_key, deserialized, &plaintext);
  if (did_succeed == DECRYPT_NEED_VERIFY) {
    if (!peacemakr_verify(verify_native_key, &plaintext, deserialized)) {
      LOGE("%s\n", "Verification of the message failed");
      peacemakr_key_free(native_key);
      return NULL;
    }
  }

  if (did_succeed == DECRYPT_FAILED) {
    LOGE("%s\n", "Decryption of the message failed");
    peacemakr_key_free(native_key);
    return NULL;
  }

  // We only want to release the byte array elements once we've successfully
  // decrypted the message
  (*env)->ReleaseByteArrayElements(env, ciphertext, raw_data, JNI_ABORT);
  peacemakr_key_free(native_key);

  // re-pack the plaintext
  jbyteArray out = (*env)->NewByteArray(env, plaintext.data_len);
  (*env)->SetByteArrayRegion(env, out, 0, plaintext.data_len,
                             (const jbyte *)plaintext.data);

  // Clean up the C plaintext
  free((void *)plaintext.data);
  free((void *)plaintext.aad);

  return out;
}

JNIEXPORT void JNICALL
Java_io_peacemakr_corecrypto_Crypto_nativeInit(JNIEnv *env, jclass clazz) {
  if (!peacemakr_init()) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"),
                     "Failed to initialize native lib");
  }
}

#ifdef __cplusplus
}
#endif
