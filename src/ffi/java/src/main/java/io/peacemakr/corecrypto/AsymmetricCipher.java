package io.peacemakr.corecrypto;

public enum AsymmetricCipher {
    ASYMMETRIC_UNSPECIFIED,
    RSA_2048,
    RSA_4096,
    ECDH_P256,
    ECDH_P384,
    ECDH_P521;

    public static AsymmetricCipher fromInt(int x) {
        switch (x) {
            case 0:
                return ASYMMETRIC_UNSPECIFIED;
            case 1:
                return RSA_2048;
            case 2:
                return RSA_4096;
            case 3:
                return ECDH_P256;
            case 4:
                return ECDH_P384;
            case 5:
                return ECDH_P521;
        }
        return null;
    }

    public int toInt() {
        switch (this) {
            case ASYMMETRIC_UNSPECIFIED:
                return 0;
            case RSA_2048:
                return 1;
            case RSA_4096:
                return 2;
            case ECDH_P256:
                return 3;
            case ECDH_P384:
                return 4;
            case ECDH_P521:
                return 5;
        }
        return 0;
    }
}
