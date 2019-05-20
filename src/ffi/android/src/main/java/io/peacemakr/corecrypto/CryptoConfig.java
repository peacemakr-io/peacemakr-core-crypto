package io.peacemakr.corecrypto;


public class CryptoConfig {
    public EncryptionMode getEncryptionMode() {
        return encryptionMode;
    }

    public void setEncryptionMode(EncryptionMode encryptionMode) {
        this.encryptionMode = encryptionMode;
    }

    public AsymmetricCipher getAsymmetricCipher() {
        return asymmetricCipher;
    }

    public void setAsymmetricCipher(AsymmetricCipher asymmetricCipher) {
        this.asymmetricCipher = asymmetricCipher;
    }

    public SymmetricCipher getSymmetricCipher() {
        return symmetricCipher;
    }

    public void setSymmetricCipher(SymmetricCipher symmetricCipher) {
        this.symmetricCipher = symmetricCipher;
    }

    public MessageDigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(MessageDigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    private EncryptionMode encryptionMode;
    private AsymmetricCipher asymmetricCipher;
    private SymmetricCipher symmetricCipher;
    private MessageDigestAlgorithm digestAlgorithm;

    CryptoConfig(EncryptionMode mode, AsymmetricCipher asymmetricCipher, SymmetricCipher symmetricCipher, MessageDigestAlgorithm digestAlgorithm) {
        this.encryptionMode = mode;
        this.asymmetricCipher = asymmetricCipher;
        this.symmetricCipher = symmetricCipher;
        this.digestAlgorithm = digestAlgorithm;
    }

    public String toString() {
        return "Config {" +
                "\n\tMode: " + getEncryptionMode().toString() +
                "\n\tSymmetric Cipher: " + getSymmetricCipher().toString() +
                "\n\tAsymmetric Cipher: " + getAsymmetricCipher().toString() +
                "\n\tDigest Algorithm: " + getDigestAlgorithm().toString() +
                "\n}";
    }
}
