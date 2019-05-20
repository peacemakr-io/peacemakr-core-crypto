package io.peacemakr.corecrypto;

public class Key {

    private long nativeKey = 0;


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

    private native void free();

    // Private constructor to make keys from pointers
    private Key(long nativeKey) {
        this.nativeKey = nativeKey;
    }

    // Public constructors
    public Key(AsymmetricCipher asymmCipher, SymmetricCipher symmCipher, RandomDevice rand) {
        newAsymmetric(asymmCipher.toInt(), symmCipher.toInt(), rand.getNativePtr());
    }

    public Key(SymmetricCipher symmCipher, RandomDevice rand) {
        newSymmetric(symmCipher.toInt(), rand.getNativePtr());
    }

    public Key(SymmetricCipher symmCipher, byte[] bytes) {
        newFromBytes(symmCipher.toInt(), bytes);
    }

    public Key(SymmetricCipher symmCipher, MessageDigestAlgorithm digestAlgorithm, String password, String salt, int iterationCount) {
        newFromPassword(symmCipher.toInt(), digestAlgorithm.toInt(), password, salt, iterationCount);
    }

    public Key(SymmetricCipher symmCipher, MessageDigestAlgorithm digestAlgorithm, Key masterKey, byte[] bytes) {
        newFromMaster(symmCipher.toInt(), digestAlgorithm.toInt(), masterKey.getNativeKey(), bytes);
    }

    public Key(AsymmetricCipher asymmCipher, SymmetricCipher symmCipher, String pemBuf, boolean isPriv) {
        if (isPriv) {
            newFromPrivPem(asymmCipher.toInt(), symmCipher.toInt(), pemBuf);
        } else {
            newFromPubPem(asymmCipher.toInt(), symmCipher.toInt(), pemBuf);
        }
    }

    public Key ECDHKeygen(SymmetricCipher symmCipher, Key peerKey) {
        long nativeDHKey = dhGenerate(symmCipher.toInt(), peerKey.getNativeKey());
        return new Key(nativeDHKey);
    }

    public CryptoConfig getConfig() {
        return new CryptoConfig(
                EncryptionMode.fromInt(getMode()),
                AsymmetricCipher.fromInt(getAsymmCipher()),
                SymmetricCipher.fromInt(getSymmCipher()),
                MessageDigestAlgorithm.fromInt(getDigestAlgorithm())
        );
    }

    // Stores the pem data in the String buf
    public native String toPrivPem();
    public native String toPubPem();

    // Stores the bytes into buf
    public native byte[] getBytes();

    public void destroy() {
        free();
    }

    private long getNativeKey() {
        return nativeKey;
    }

}