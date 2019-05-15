package io.peacemakr.corecrypto;

public class Key {
    static {
        System.loadLibrary("peacemakr-core-crypto-jni");
    }

    long nativeKey = 0;


    private native void newAsymmetric(int asymm_cipher, int symm_cipher, long rand);
    private native void newSymmetric(int symm_cipher, long rand);
    private native void newFromBytes(int symm_cipher, byte[] buf);
    private native void newFromPassword(int symm_cipher, int digest_algorithm, String password, String salt, int iteration_count);
    private native void newFromMaster(int symm_cipher, int digest_algorithm, long master_key, byte[] buf);
    private native void newFromPubPem(int asymm_cipher, int symm_cipher, String buf);
    private native void newFromPrivPem(int asymm_cipher, int symm_cipher, String buf);

    /**
     * Returns a new pointer to a peacemakr_key_t to be used in returning aa new Key object
     */
    private native long dhGenerate(int symm_cipher, long peer_key);

    // Instead of getting the whole config object, get pieces of it (to make JNI easier)
    // We can wrap these up on the Java side if required/desired.
    private native int getMode();
    private native int getSymmCipher();
    private native int getAsymmCipher();
    private native int getDigestAlgorithm();

    // Stores the pem data in the String buf
    private native String toPrivPem();
    private native String toPubPem();

    // Stores the bytes into buf
    private native byte[] getBytes();

    private native void free();


    // Private constructor to make keys from pointers
    private Key(long nativeKey) {
        this.nativeKey = nativeKey;
    }

    // Public constructors
//    public Key(AsymmetricCipher asymmCipher, SymmetricCipher symmCipher, RandomDevice rand) {
//        nativeKey = newAsymmetric(asymmCipher.getcIdx(), symmCipher.getcIdx(), rand.getNativePtr());
//    }
//
//    public Key(SymmetricCipher symmCipher, RandomDevice rand) {
//        nativeKey = newSymmetric(symmCipher.getcIdx(), rand.getNativePtr());
//    }

}