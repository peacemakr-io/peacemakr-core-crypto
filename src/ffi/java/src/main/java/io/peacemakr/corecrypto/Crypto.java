package io.peacemakr.corecrypto;

public class Crypto {
    static {
        System.loadLibrary("peacemakr-core-crypto-jni");
    }

    enum SymmetricCryptoTypes {
        AES_GCM_128,
        AES_GSM_192,
        AES_GCM_256,
        CHACHA20_POLY1902
    }

    public native static byte[] encryptSymmetric(byte[] key,
                                                 byte[] keyId,
                                                 AsymmetricKey signingKey,
                                                 byte[] signingKeyId,
                                                 byte[] plaintext,
                                                 SymmetricCryptoTypes mode);

    public native static byte[] getEncryptingKeyIdFromCiphertext(byte[] ciphertext);

    public native static byte[] getSigningKeyIdFromCiphertext(byte[] ciphertext);

    public native static byte[] decryptSymmetric(byte[] key, AsymmetricKey verificationKey, byte[] ciphertext);

    public native static byte[] decryptAsymmetric(AsymmetricKey key, byte[] ciphertext);
}