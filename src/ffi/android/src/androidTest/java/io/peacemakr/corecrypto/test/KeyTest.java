package io.peacemakr.corecrypto.test;

import io.peacemakr.corecrypto.Key;

import org.junit.Test;

public class KeyTest {

    @Test
    public void testJNI() {
        Key key = new Key();

        String result = key.peacemakr_key_new_asymmetric(1, 2, 3);

        System.out.println(result);
    }
}