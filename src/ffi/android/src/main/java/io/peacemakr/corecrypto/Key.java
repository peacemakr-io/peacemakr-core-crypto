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
    private native long newAsymmetric(int asymm_cipher, int symm_cipher, long rand);
    private native long newSymmetric(int symm_cipher, long rand);

    public Key(AsymmetricCipher asymmCipher, SymmetricCipher symmCipher, RandomDevice rand) {
        nativeKey = newAsymmetric(asymmCipher.getcIdx(), symmCipher.getcIdx(), rand.getNativePtr());
    }

    public Key(SymmetricCipher symmCipher, RandomDevice rand) {
        nativeKey = newSymmetric(symmCipher.getcIdx(), rand.getNativePtr());
    }

}