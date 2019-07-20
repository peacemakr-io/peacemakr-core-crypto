package io.peacemakr.corecrypto;

import cz.adamh.utils.NativeUtils;
import java.io.IOException;
import java.lang.RuntimeException;

public class Crypto {

    public static boolean isWindows() {
        System.getProperty("os.name").toLowerCase();
        return (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0);
    }

    public static boolean isMac() {
        return (System.getProperty("os.name").toLowerCase().indexOf("mac") >= 0);
    }

    public static boolean isUnix() {
        String OS = System.getProperty("os.name").toLowerCase();
        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0 );
    }

    public static boolean isSolaris() {
        return (System.getProperty("os.name").toLowerCase().indexOf("sunos") >= 0);
    }

    static {
        try {
            if (isMac()) {
                NativeUtils.loadLibraryFromJar("/libpeacemakr-core-crypto-jni.dylib");
            } else if (isUnix()) {
                NativeUtils.loadLibraryFromJar("/libpeacemakr-core-crypto-jni.os");
            } else {
                throw new RuntimeException("Unsupported OS Detected, of " + System.getProperty("os.name").toLowerCase());
            }
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