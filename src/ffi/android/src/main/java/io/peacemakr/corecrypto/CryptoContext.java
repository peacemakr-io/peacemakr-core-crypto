package io.peacemakr.corecrypto;

public class CryptoContext {

    private native void init();

    private native void ciphertextBlobFree(long blobAddr);

    // Returns a pointer to a ciphertext blob
    private native long encrypt(long recipientKey, long plaintext, long rand);

    // Signs the ciphertext blob
    private native void sign(long senderKey, long plaintext, int digest, long ciphertextBlob);

    // Decrypts into plaintext
    private native int decrypt(long recipientKey, long ciphertextBlob, long plaintext);

    // Extracts into plaintext
    private native boolean getUnverifiedAAD(long ciphertextBlob, long plaintext);

    private native boolean verify(long recipientKey, long plaintext, long ciphertextBlob);

    private native byte[] hmac(int digest, long masterKey, byte[] buf);

    private native byte[] serialize(int digest, long ciphertextBlob);

    // TODO: may run into lots of trouble here...
    private native long deserialize(byte[] serialized, int mode, int symmCipher, int asymmCipher, int digest);
}