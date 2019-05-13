package io.peacemakr.corecrypto;

public enum AsymmetricCipher {
    ASYMMETRIC_UNSPECIFIED(0), RSA_2048(1), RSA_4096(2), ECDH_P256(3), ECDH_P384(4), ECDH_P521(5);

    public int getcIdx() {
        return cIdx;
    }

    private final int cIdx;
    private AsymmetricCipher(int cIdx) {
        this.cIdx = cIdx;
    }
}
