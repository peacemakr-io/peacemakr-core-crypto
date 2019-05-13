package io.peacemakr.corecrypto;

public enum MessageDigestAlgorithm {
    DIGEST_UNSPECIFIED(0), SHA_224(1), SHA_256(2), SHA_384(3), SHA_512(4);

    public int getcIdx() {
        return cIdx;
    }

    private final int cIdx;
    private MessageDigestAlgorithm(int cIdx) {
        this.cIdx = cIdx;
    }
}
