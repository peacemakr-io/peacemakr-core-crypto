package io.peacemakr.corecrypto;

public class RandomDevice {
    private long nativePtr;

    long getNativePtr() {
        return nativePtr;
    }

    native int generate(byte[] recipientBuf);
    native String error(int errorCode);
}