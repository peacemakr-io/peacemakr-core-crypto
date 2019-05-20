package io.peacemakr.corecrypto;

public class RandomDevice {
    // Gets the native JNI static object
    native long getNativePtr();

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