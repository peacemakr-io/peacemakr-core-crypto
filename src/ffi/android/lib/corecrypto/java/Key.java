package io.peacemakr.corecrypto.jni;

public class Key {
    static {
        System.loadLibrary("peacemakr-core-crypto");
    }

    private long nativeKey;

    public Key(CryptoConfig cfg, RandomDevice rand) {
        ;
    }
}