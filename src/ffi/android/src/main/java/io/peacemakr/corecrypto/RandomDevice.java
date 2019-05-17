package io.peacemakr.corecrypto;

public class RandomDevice {
    private long nativePtr;

    long getNativePtr() {
        return nativePtr;
    }

    // TODO: these need to be callbacks into the java code...AKA C should call java
    native int generate(byte[] recipientBuf);
    native String error(int errorCode);
}