package io.peacemakr.corecrypto;

import cz.adamh.utils.NativeUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

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
    }
}
