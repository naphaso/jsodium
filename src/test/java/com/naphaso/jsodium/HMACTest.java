package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 23/07/16.
 */
public class HMACTest extends TestCase {
    public static final int DATA_SIZE = 4000;

    @Test
    public void test_crypto_auth() {
        byte[] data = new byte[DATA_SIZE];
        byte[] key = new byte[Sodium.crypto_auth_KEYBYTES];
        byte[] hash = new byte[Sodium.crypto_auth_BYTES];

        Sodium.randombytes_buf(data);

        assertTrue(Sodium.crypto_auth(hash, data, key) == 0);
        assertTrue(Sodium.crypto_auth_verify(hash, data, key) == 0);
        data[0] = (byte) (data[0] ^ 1);
        assertFalse(Sodium.crypto_auth_verify(hash, data, key) == 0);
    }

    @Test
    public void test_crypto_auth_hmac_sha256() {

    }

    @Test
    public void test_crypto_auth_hmac_sha512() {

    }

    @Test
    public void test_crypto_auth_hmac_sha512256() {
        byte[] data = new byte[DATA_SIZE];
        byte[] key = new byte[Sodium.crypto_auth_hmacsha512256_KEYBYTES];
        byte[] hash = new byte[Sodium.crypto_auth_hmacsha512256_BYTES];

        Sodium.randombytes_buf(data);

        assertTrue(Sodium.crypto_auth_hmacsha512256(hash, data, key) == 0);
        assertTrue(Sodium.crypto_auth_hmacsha512256_verify(hash, data, key) == 0);
        data[0] = (byte) (data[0] ^ 1);
        assertFalse(Sodium.crypto_auth_verify(hash, data, key) == 0);
    }


    @Test
    public void test_crypto_auth_hmac_sha256_state() {

    }

    @Test
    public void test_crypto_auth_hmac_sha512_state() {

    }

    @Test
    public void test_crypto_auth_hmac_sha512256_state() {
        byte[] data = new byte[DATA_SIZE];
        byte[] key = new byte[Sodium.crypto_auth_hmacsha512256_KEYBYTES];
        byte[] hash = new byte[Sodium.crypto_auth_hmacsha512256_BYTES];
        byte[] state = new byte[Sodium.crypto_auth_hmacsha512256_statebytes()];

        Sodium.randombytes_buf(data);

        assertTrue(Sodium.crypto_auth_hmacsha512256_init(state, key) == 0);
        assertTrue(Sodium.crypto_auth_hmacsha512256_update(state, data) == 0);
        assertTrue(Sodium.crypto_auth_hmacsha512256_final(state, hash) == 0);

        assertTrue(Sodium.crypto_auth_hmacsha512256_verify(hash, data, key) == 0);
        data[0] = (byte) (data[0] ^ 1);
        assertFalse(Sodium.crypto_auth_hmacsha512256_verify(hash, data, key) == 0);
    }
}

