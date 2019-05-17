package io.peacemakr.corecrypto;

public enum EncryptionMode {
    SYMMETRIC,
    ASYMMETRIC;

    public static EncryptionMode fromInt(int x) {
        switch (x) {
            case 0:
                return SYMMETRIC;
            case 1:
                return ASYMMETRIC;
        }
        return null;
    }

    public int toInt() {
        switch (this) {
            case SYMMETRIC:
                return 0;
            case ASYMMETRIC:
                return 1;
        }
        return -1;
    }
}
