package io.peacemakr.corecrypto.jni;

public class Key {
    static {
        System.loadLibrary("peacemakr-core-crypto");
    }

    private long nativeKey;

    // TODO
//    private native PeacemakrKey_new()

    public Key(CryptoConfig cfg, RandomDevice rand) {
        ;
    }
}