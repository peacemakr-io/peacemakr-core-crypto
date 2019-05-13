package io.peacemakr.corecrypto;

public enum SymmetricCipher {
    SYMMETRIC_UNSPECIFIED(0), AES_128_GCM(1), AES_192_GCM(2), AES_256_GCM(3), CHACHA20_POLY1305(4);


    public int getcIdx() {
        return cIdx;
    }

    private final int cIdx;
    private SymmetricCipher(int cIdx) {
        this.cIdx = cIdx;
    }
}
