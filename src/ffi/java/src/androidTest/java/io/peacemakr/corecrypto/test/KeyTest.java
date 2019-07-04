package io.peacemakr.corecrypto.test;

import io.peacemakr.corecrypto.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import android.support.test.runner.AndroidJUnit4;

@RunWith(AndroidJUnit4.class)
public class KeyTest {

    private RandomDevice rand = new RandomDevice();

    @Test
    public void testAsymmetric() {
        // TODO: why does symmetric key generation crash?
        Key key = new Key(AsymmetricCipher.RSA_4096, SymmetricCipher.CHACHA20_POLY1305, rand);
        System.out.println(key.getConfig().toString());
    }

    @Test
    public void testSymmetric() {
        // TODO: why does symmetric key generation crash?
        Key key = new Key(SymmetricCipher.CHACHA20_POLY1305, rand);
        System.out.println(key.getConfig().toString());
    }
}