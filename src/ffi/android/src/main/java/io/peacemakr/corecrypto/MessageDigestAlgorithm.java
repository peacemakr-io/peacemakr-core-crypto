package io.peacemakr.corecrypto;

public enum MessageDigestAlgorithm {
    DIGEST_UNSPECIFIED,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512;

    public static MessageDigestAlgorithm fromInt(int x) {
        switch (x) {
            case 0:
                return DIGEST_UNSPECIFIED;
            case 1:
                return SHA_224;
            case 2:
                return SHA_256;
            case 3:
                return SHA_384;
            case 4:
                return SHA_512;
        }
        return null;
    }

    public int toInt() {
        switch (this) {
            case DIGEST_UNSPECIFIED:
                return 0;
            case SHA_224:
                return 1;
            case SHA_256:
                return 2;
            case SHA_384:
                return 3;
            case SHA_512:
                return 4;
        }
        return 0;
    }
}
