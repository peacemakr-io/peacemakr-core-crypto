package io.peacemakr.corecrypto;

public class Crypto {
    static {
        System.loadLibrary("peacemakr-core-crypto-jni");
    }

    public enum SymmetricCryptoTypes {
        AES_GCM_128,
        AES_GSM_192,
        AES_GCM_256,
        CHACHA20_POLY1902
    }

    public enum AsymmetricCryptoTypes {
        RSA_2048,
        RSA_4096,
        EC_256,
        EC_384,
        EC_521
    }

    public native static AsymmetricKey genKeypairFromPubPem(String pub);

    public native static AsymmetricKey genKeypairFromPrivPem(String priv);

    public native static AsymmetricKey genKeypairFromPRNG(AsymmetricCryptoTypes type);

    public native static byte[] encryptSymmetric(byte[] key,
                                                 byte[] keyId,
                                                 AsymmetricKey signingKey,
                                                 byte[] signingKeyId,
                                                 byte[] plaintext,
                                                 SymmetricCryptoTypes mode);

    public native static byte[] getEncryptingKeyIdFromCiphertext(byte[] ciphertext);

    public native static byte[] getSigningKeyIdFromCiphertext(byte[] ciphertext);

    public native static byte[] decryptSymmetric(byte[] key,
                                                 AsymmetricKey verificationKey,
                                                 byte[] ciphertext);

    public native static byte[] decryptAsymmetric(AsymmetricKey key,
                                                  byte[] ciphertext);
}