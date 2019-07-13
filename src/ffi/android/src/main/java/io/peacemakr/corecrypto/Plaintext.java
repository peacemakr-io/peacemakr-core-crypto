package io.peacemakr.corecrypto;

public class Plaintext {
    private byte[] data;
    private byte[] aad;

    native void fromNative(long plaintextNative);
    native long toNative();

    Plaintext(byte[] data, byte[] aad) {
        this.data = data.clone();
        this.aad = aad.clone();
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getAAD() {
        return aad;
    }
}