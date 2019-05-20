package io.peacemakr.corecrypto;

public class CryptoContext {
    static {
        System.loadLibrary("peacemakr-core-crypto-jni");
    }

    private static native void init();

    private static native void ciphertextBlobFree(long blobAddr);

    // Returns a pointer to a ciphertext blob
    private static native long encrypt(long recipientKey, long plaintext, long rand);

    // Signs the ciphertext blob
    private static native void sign(long senderKey, long plaintext, int digest, long ciphertextBlob);

    // Decrypts into plaintext
    private static native int decrypt(long recipientKey, long ciphertextBlob, long plaintext);

    // Extracts into plaintext
    private static native boolean getUnverifiedAAD(long ciphertextBlob, long plaintext);

    private static native boolean verify(long senderKey  , long plaintext, long ciphertextBlob);

    private static native byte[] hmac(int digest, long masterKey, byte[] buf);

    private static native byte[] serialize(int digest, long ciphertextBlob);

    // TODO: will have to return the crypto config of the serialized thing too...
    private static native long deserialize(byte[] serialized);
}