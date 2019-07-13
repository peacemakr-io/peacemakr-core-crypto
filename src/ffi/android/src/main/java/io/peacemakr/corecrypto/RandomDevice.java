package io.peacemakr.corecrypto;

public class RandomDevice {
    // Gets the native JNI static object
    native long getNativePtr();

    protected native void registerNative();

    public RandomDevice() {
        registerNative();
    }
}