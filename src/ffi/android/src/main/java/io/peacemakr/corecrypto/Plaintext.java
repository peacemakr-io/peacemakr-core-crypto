package io.peacemakr.corecrypto;

public class Plaintext {
    private byte[] data;
    private byte[] aad;

    private native void fromNative(long plaintextNative);

    public byte[] getData() {
        return data;
    }

    public byte[] getAAD() {
        return aad;
    }
}