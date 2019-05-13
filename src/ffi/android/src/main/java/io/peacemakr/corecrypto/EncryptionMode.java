package io.peacemakr.corecrypto;

public enum EncryptionMode {
    SYMMETRIC(0), ASYMMETRIC(1);

    public int getcIdx() {
        return cIdx;
    }

    private final int cIdx;
    private EncryptionMode(int cIdx) {
        this.cIdx = cIdx;
    }
}
