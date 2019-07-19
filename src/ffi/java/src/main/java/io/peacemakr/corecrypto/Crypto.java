package io.peacemakr.corecrypto;

import cz.adamh.utils.NativeUtils;
import java.io.IOException;

public class Crypto {
    static {
        try {
            NativeUtils.loadLibraryFromJar("peacemakr-core-crypto-jni");
        } catch (IOException e) {
            System.err.println("Failed to laod the native jni crypto from jar due to " + e.getMessage());
        }

    }

    public enum MessageDigest {
        SHA_224,
        SHA_256,
        SHA_384,
        SHA_512
    }

    public native static byte[] encryptSymmetric(byte[] encryptionKey,
                                                 SymmetricCipher mode,
                                                 AsymmetricKey signingKey,
                                                 byte[] plaintext,
                                                 byte[] aad, // have to pack the key IDs in here on your own
                                                 MessageDigest digestType);

    public native static byte[] getCiphertextAAD(byte[] ciphertext);

    public native static byte[] decryptSymmetric(byte[] key,
                                                 SymmetricCipher mode,
                                                 AsymmetricKey verificationKey,
                                                 byte[] ciphertext);

    public native static byte[] decryptAsymmetric(AsymmetricKey key,
                                                  byte[] ciphertext);
}