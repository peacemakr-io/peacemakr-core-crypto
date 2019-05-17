package io.peacemakr.corecrypto;

public class RandomDevice {
    protected long nativePtr = 0;
    public long getNativePtr() {
        return nativePtr;
    }

    protected native void registerNative();

    public RandomDevice() {
        registerNative();
    }

    static public int generate(byte[] recipientBuf) {
        // To be implemented by subclass
        return -1;
    }

    static public String error(int errorCode) {
        // To be implemented by subclass
        return "";
    }
}