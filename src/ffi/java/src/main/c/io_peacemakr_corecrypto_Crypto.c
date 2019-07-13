

#include <jni.h>
#include "io_peacemakr_corecrypto_Crypto.h"

// TODO: include crypto.h and implement these.


/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    genKeypair
 * Signature: (Lio/peacemakr/corecrypto/Crypto/AsymmetricCryptoTypes;Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_io_peacemakr_corecrypto_Crypto_genKeypair
  (JNIEnv *jniEnv,
  jclass c,
  jobject type,
  jstring priv,
  jstring pub) {

  return;

}


/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    encryptSymmetric
 * Signature: ([B[BLio/peacemakr/corecrypto/AsymmetricKey;[B[BLio/peacemakr/corecrypto/Crypto/SymmetricCryptoTypes;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_peacemakr_corecrypto_Crypto_encryptSymmetric
  (JNIEnv *jniEnv, 
  	jclass c, 
  	jbyteArray key, 
  	jbyteArray keyId, 
  	jobject signingKey, 
  	jbyteArray signingKeyId, 
  	jbyteArray plaintext, 
  	jobject mode) {

  	return NULL;
}

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    getEncryptingKeyIdFromCiphertext
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_peacemakr_corecrypto_Crypto_getEncryptingKeyIdFromCiphertext
  (JNIEnv *jniEnv,
  	jclass c,
  	jbyteArray ciphertext) {

  	return NULL;
}

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    getSigningKeyIdFromCiphertext
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_peacemakr_corecrypto_Crypto_getSigningKeyIdFromCiphertext
  (JNIEnv *jniEnv,
  	jclass c,
  	jbyteArray ciphertext) {

  	return NULL;
}

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    decryptSymmetric
 * Signature: ([BLio/peacemakr/corecrypto/AsymmetricKey;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_peacemakr_corecrypto_Crypto_decryptSymmetric
  (JNIEnv *jniEnv,
  	jclass c,
  	jbyteArray key,
  	jobject verificationKey,
  	jbyteArray ciphertext) {

  	return NULL;
}

/*
 * Class:     io_peacemakr_corecrypto_Crypto
 * Method:    decryptAsymmetric
 * Signature: (Lio/peacemakr/corecrypto/AsymmetricKey;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_io_peacemakr_corecrypto_Crypto_decryptAsymmetric
  (JNIEnv *jniEnv,
  	jclass c,
  	jobject asymmetricKey,
  	jbyteArray ciphertext) {

  	return NULL;
}
