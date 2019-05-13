package io.peacemakr.corecrypto;

public class Key {
    static {
        System.loadLibrary("peacemakr-core-crypto-jni");
    }

    private long nativeKey;

    // C signature:
    // peacemakr_key_t *peacemakr_key_new_asymmetric(asymmetric_cipher asymm_cipher,
    //                                               symmetric_cipher symm_cipher,
    //                                               random_device_t *rand);
    public native String peacemakr_key_new_asymmetric(int asymm_cipher, int symm_cipher, long rand);
}