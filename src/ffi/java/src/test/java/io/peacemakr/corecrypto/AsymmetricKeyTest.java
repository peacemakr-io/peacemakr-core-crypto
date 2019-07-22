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
}
