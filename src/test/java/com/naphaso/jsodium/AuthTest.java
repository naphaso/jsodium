package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 23/07/16.
 */
public class AuthTest extends TestCase {
    public static final int DATA_SIZE = 4000;

    @Test
    public void test_crypto_auth() {
        byte[] data = new byte[DATA_SIZE];
        byte[] key = new byte[Sodium.crypto_auth_KEYBYTES];
        byte[] hash = new byte[Sodium.crypto_auth_BYTES];

        Sodium.randombytes_buf(data);

        assertTrue(Sodium.crypto_auth(hash, data, key) == 0);
        assertTrue(Sodium.crypto_auth_verify(hash, data, key) == 0);
    }
}
