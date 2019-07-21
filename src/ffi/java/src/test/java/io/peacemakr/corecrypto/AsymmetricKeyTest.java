package io.peacemakr.corecrypto;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

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
        System.out.println(key.getPrivPemStr());

        AsymmetricKey peerKey = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.CHACHA20_POLY1305);
        byte[] symmKey = key.ecdhKeygen(SymmetricCipher.CHACHA20_POLY1305, peerKey);
        System.out.println(Arrays.toString(symmKey));
    }

    @Test
    public void encrypt() throws Exception {
        AsymmetricKey key = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.SYMMETRIC_UNSPECIFIED);

        AsymmetricKey peerKey = AsymmetricKey.fromPRNG(AsymmetricCipher.ECDH_P256, SymmetricCipher.SYMMETRIC_UNSPECIFIED);
        byte[] symmKey = key.ecdhKeygen(SymmetricCipher.CHACHA20_POLY1305, peerKey);

//        byte[] plaintext = "Hello, world!".getBytes();
//        byte[] aad = "AAD".getBytes();
//
//        byte[] encrypted = Crypto.encryptSymmetric(symmKey, SymmetricCipher.CHACHA20_POLY1305, key, plaintext, aad, Crypto.MessageDigest.SHA_256);
//        byte[] decrypted = Crypto.decryptSymmetric(symmKey, key, encrypted);
//
//        Assert.assertArrayEquals(plaintext, decrypted);
    }
}
