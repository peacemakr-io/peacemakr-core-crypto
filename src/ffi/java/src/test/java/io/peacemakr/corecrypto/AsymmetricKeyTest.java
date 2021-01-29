package io.peacemakr.corecrypto;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class AsymmetricKeyTest {

    @Before
    public void setUp() throws Exception {
        Crypto.init();
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void newKey() throws Exception {
        AsymmetricKey key = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.CHACHA20_POLY1305);

        String pubPem = key.getPubPemStr();
        String privPem = key.getPrivPemStr();

        AsymmetricKey pubFromPem = AsymmetricKey.fromPubPem(SymmetricCipher.CHACHA20_POLY1305, pubPem);
        AsymmetricKey privFromPem = AsymmetricKey.fromPrivPem(SymmetricCipher.CHACHA20_POLY1305, privPem);

        Assert.assertEquals(pubPem, pubFromPem.getPubPemStr());
        Assert.assertEquals(privPem, privFromPem.getPrivPemStr());
    }

    @Test
    public void usesOldCoreCrypto() throws Exception {
        String validCiphertextFromKD = "AAAEHgAAAwsAAAAAAgAAAAEBBAEAAAEAAAAAAJVkfmpiAYBoCnczS0c2GS2p2foFJhPnfAM2" +
                "T1vBpxJP3m969yQsjBhJoEl9tzXf3Mv/64t67WiC5j1pUez306bMmivI9eK75S0+bGYpAQnm" +
                "lRauvETENzmLCvCuYCr8NxfAheCvEnJx83WGxW2rXpIqlDXh9r/UUGE9W0MnTTBeAv+Ef/Jy" +
                "o8HTwUYez4LgRk7I47dqYHcCqb8OZ0TCAjVMSECjlKNwZ7iTOqo0h+IQVAsOaGF1HUUh73jM" +
                "feOx4M16s9UlS5LI7/TH9UY4D20C7nG7FguRvQsPnCWD+6Du1KeELeLOpZpEoL1HPVCXI67l" +
                "TOU4dlopObYJuFINShgAAAAQAAAAAIp+RsLFQCaRoQ0CSwAAAAAAAAAQAAAAAHLIqUwVG5Ce" +
                "ZbAwya3XFUYAAABPAAAAAHsiY3J5cHRvS2V5SUQiOiIiLCJzZW5kZXJLZXlJRCI6IjNacEx1" +
                "VDR1djhUTHFSTHlHTXFVQ09xelhQRjQwVldKREF1M1dqaDgrdTA9In0AAABYAAAAABvS1+k5" +
                "CLtBSWuDKVW/Rxbygr5aioJQT2lPsptxSMxwtfWDSqHOqkdoOyx6m+iIX9UPJt72y2TeWWVD" +
                "TFrH+mmHNsOfok83qcP7MYhxnfqsgjlnPrCj2/cAAAEAAAAAAGXL48F/0Z8NRBtHpjVPM0KS" +
                "UBVkZU0Dl0sivWjlGpofTBWBiTXWrkE2LlnyNsLiLexTJVCMkyXRsOPjC9xMztTO3tirO+Ue" +
                "ygfvRuEJBj9s1hKrVO+3ynTgpMGMPXaRvrBQaRmyqZsdY4ALciyEMaXSBEbIPIExxubBuH11" +
                "YUO3YCyopO7DZmyv1gUQXsj+v6ETTxjNZtR+3RgUm4pwaVoE0+U49FZBxcLhSk+CtAZrnJ9Q" +
                "zp6T5GSjcP5e1SaUwRahW2CksF6IEn+15aekL8hkfw2ymdaHgT9tReqoCHi6aAtqIFePa56t" +
                "O3Ks+BF4VYGGx4QHp82jyLQ1pSvJNWAAAAAgAAAAAM4oJerNH9Vj3mQHp+jRsSPg6ncz2b9S" +
                "7kH8OVSwQJ4y";
        byte[] aad = Crypto.getCiphertextAAD(validCiphertextFromKD.getBytes());
        Assert.assertNull(aad);
    }


    @Test
    public void encrypt() throws Exception {
        AsymmetricKey key = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.SYMMETRIC_UNSPECIFIED);

        AsymmetricKey peerKey = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.SYMMETRIC_UNSPECIFIED);
        byte[] symmKey = key.ecdhKeygen(SymmetricCipher.CHACHA20_POLY1305, peerKey);

        byte[] plaintext = "Hello, world!".getBytes();
        byte[] aad = "AAD".getBytes();

        byte[] encrypted = Crypto.encryptSymmetric(symmKey, SymmetricCipher.CHACHA20_POLY1305, key, plaintext, aad, MessageDigest.SHA_256);
        byte[] gotAAD = Crypto.getCiphertextAAD(encrypted);
        Assert.assertArrayEquals(aad, gotAAD);

        byte[] decrypted = Crypto.decryptSymmetric(symmKey, key, encrypted);
        Assert.assertArrayEquals(plaintext, decrypted);
    }

    @Test
    public void sign() throws Exception {
        AsymmetricKey key = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.SYMMETRIC_UNSPECIFIED);

        byte[] plaintext = "Hello, world!".getBytes();
        byte[] aad = "AAD".getBytes();

        byte[] encrypted = Crypto.signAsymmetric(key, plaintext, aad, MessageDigest.SHA_256);
        byte[] gotAAD = Crypto.getCiphertextAAD(encrypted);
        Assert.assertArrayEquals(aad, gotAAD);

        byte[] verified = Crypto.verifyAsymmetric(symmKey, key, encrypted);
        Assert.assertArrayEquals(plaintext, verified);
    }

    @Test
    public void encryptNoAAD() throws Exception {
        AsymmetricKey key = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.SYMMETRIC_UNSPECIFIED);

        AsymmetricKey peerKey = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.SYMMETRIC_UNSPECIFIED);
        byte[] symmKey = key.ecdhKeygen(SymmetricCipher.CHACHA20_POLY1305, peerKey);

        byte[] plaintext = "Hello, world!".getBytes();
        byte[] aad = new byte[]{};

        byte[] encrypted = Crypto.encryptSymmetric(symmKey, SymmetricCipher.CHACHA20_POLY1305, key, plaintext, aad, MessageDigest.SHA_256);

        byte[] decrypted = Crypto.decryptSymmetric(symmKey, key, encrypted);
        Assert.assertArrayEquals(plaintext, decrypted);
    }
}
