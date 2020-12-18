package io.peacemakr.corecrypto;

import java.io.IOException;
import java.lang.RuntimeException;

public class Crypto {

    public static void init() {
        // Need to call something to trip the JVM to hit the static load block of this class.
        nativeInit();
    }

    static {
        try {
            // This order is very important, don't flip.
            System.loadLibrary("peacemakr-core-crypto");
            System.loadLibrary("peacemakr-core-crypto-jni");
        } catch (Exception e) {
            System.err.println("Failed to load the native jni crypto from jar due to " + e.getMessage());
        }
    }

    public native static byte[] encryptSymmetric(byte[] encryptionKey,
                                                 SymmetricCipher mode,
                                                 AsymmetricKey signingKey,
                                                 byte[] plaintext,
                                                 byte[] aad, // have to pack the key IDs in here on your own
                                                 MessageDigest digestType);

    public native static byte[] getCiphertextAAD(byte[] ciphertext);

    public native static byte[] decryptSymmetric(byte[] key,
                                                 AsymmetricKey verificationKey,
                                                 byte[] ciphertext);

    public native static byte[] decryptAsymmetric(AsymmetricKey key,
                                                  AsymmetricKey verificationKey,
                                                  byte[] ciphertext);

    private native static void nativeInit();
}