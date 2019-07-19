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

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    encryptSymmetric
 * Signature:
 * ([BLio/peacemakr/corecrypto/SymmetricCipher;Lio/peacemakr/corecrypto/AsymmetricKey;[B[BLio/peacemakr/corecrypto/Crypto/MessageDigest;)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_encryptSymmetric(
    JNIEnv *env, jclass clazz, jbyteArray key, jobject symm_cipher,
    jobject sign_key, jbyteArray plaintext, jbyteArray aad, jobject digest) {
  return NULL;
}

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    getCiphertextAAD
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_getCiphertextAAD(JNIEnv *env, jclass clazz,
                                                     jbyteArray ciphertext) {
  return NULL;
}

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    decryptSymmetric
 * Signature:
 * ([BLio/peacemakr/corecrypto/SymmetricCipher;Lio/peacemakr/corecrypto/AsymmetricKey;[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_decryptSymmetric(JNIEnv *env, jclass clazz,
                                                     jbyteArray key,
                                                     jobject symm_cipher,
                                                     jobject verify_key,
                                                     jbyteArray ciphertext) {
  return NULL;
}

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    decryptAsymmetric
 * Signature: (Lio/peacemakr/corecrypto/AsymmetricKey;[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_io_peacemakr_corecrypto_Crypto_decryptAsymmetric(JNIEnv *env, jclass clazz,
                                                      jobject key,
                                                      jbyteArray ciphertext) {
  peacemakr_key_t *native_key = getNativeKey(env, key);
  crypto_config_t native_key_config = peacemakr_key_get_config(native_key);
  if (native_key_config.asymm_cipher == RSA_2048 ||
      native_key_config.asymm_cipher == RSA_4096) {
    LOGE("%s\n", "Cannot call decryptAsymmetric with non-RSA key. For EC keys "
                 "call ecdhKeygen to create the symmetric encryption key and "
                 "use the symmetric functions.");
    return NULL;
  }

  // TODO: do the decrypt, deserialize, etc.

  return NULL;
}

#ifdef __cplusplus
}
#endif
