package io.peacemakr.corecrypto;

import cz.adamh.utils.NativeUtils;
import java.io.IOException;
import java.lang.RuntimeException;

public class Crypto {

    public static void init() {
        // Need to call something to trip the JVM to hit the static load block of this class.
        nativeInit();
    }

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
                // This order is very important, don't flip.
                NativeUtils.loadLibraryFromJar("/lib/libpeacemakr-core-crypto.dylib");
                NativeUtils.loadLibraryFromJar("/lib/libpeacemakr-core-crypto-jni.dylib");
            } else if (isUnix()) {
                // This order is very important, don't flip.
                NativeUtils.loadLibraryFromJar("/lib/libpeacemakr-core-crypto.so");
                NativeUtils.loadLibraryFromJar("/lib/libpeacemakr-core-crypto-jni.so");
            } else {
                throw new RuntimeException("Unsupported OS Detected, of " + System.getProperty("os.name").toLowerCase());
            }
        } catch (IOException e) {
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