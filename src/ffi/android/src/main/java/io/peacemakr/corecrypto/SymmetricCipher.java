package io.peacemakr.corecrypto;

public enum SymmetricCipher {
    SYMMETRIC_UNSPECIFIED,
    AES_128_GCM,
    AES_192_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305;

    public static SymmetricCipher fromInt(int x) {
        switch (x) {
            case 0:
                return SYMMETRIC_UNSPECIFIED;
            case 1:
                return AES_128_GCM;
            case 2:
                return AES_192_GCM;
            case 3:
                return AES_256_GCM;
            case 4:
                return CHACHA20_POLY1305;
        }
        return null;
    }

    public int toInt() {
        switch (this) {
            case SYMMETRIC_UNSPECIFIED:
                return 0;
            case AES_128_GCM:
                return 1;
            case AES_192_GCM:
                return 2;
            case AES_256_GCM:
                return 3;
            case CHACHA20_POLY1305:
                return 4;
        }
        return 0;
    }
}
