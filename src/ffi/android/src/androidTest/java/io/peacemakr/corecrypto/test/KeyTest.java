package io.peacemakr.corecrypto.test;

import io.peacemakr.corecrypto.AsymmetricCipher;
import io.peacemakr.corecrypto.Key;

import io.peacemakr.corecrypto.RandomDevice;
import io.peacemakr.corecrypto.SymmetricCipher;
import org.junit.Test;
import org.junit.runner.RunWith;
import android.support.test.runner.AndroidJUnit4;

@RunWith(AndroidJUnit4.class)
public class KeyTest {

    @Test
    public void testJNI() {
        RandomDevice rand = new RandomDevice();
        Key key = new Key(AsymmetricCipher.ECDH_P256, SymmetricCipher.CHACHA20_POLY1305, rand);
    }
}