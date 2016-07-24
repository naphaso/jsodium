package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 23/07/16.
 */
public class SignTest extends TestCase {
    public static final int MESSAGE_SIZE = 4000;

    @Test
    public void test_crypto_sign() {
        byte[] message = new byte[MESSAGE_SIZE];
        byte[] message2 = new byte[MESSAGE_SIZE];
        byte[] publicKey = new byte[Sodium.crypto_sign_PUBLICKEYBYTES];
        byte[] secretKey = new byte[Sodium.crypto_sign_SECRETKEYBYTES];
        byte[] signedMessage = new byte[Sodium.crypto_sign_BYTES + MESSAGE_SIZE];

        Sodium.randombytes_buf(message);

        assertTrue(Sodium.crypto_sign_keypair(publicKey, secretKey) == 0);
        assertTrue(Sodium.crypto_sign(signedMessage, message, secretKey) >= 0);
        assertTrue(Sodium.crypto_sign_open(message2, signedMessage, publicKey) >= 0);
        assertEquals(Utils.encode(message), Utils.encode(message2));

        signedMessage[0] = (byte) (signedMessage[0] ^ 1);

        assertFalse(Sodium.crypto_sign_open(message2, signedMessage, publicKey) >= 0);
    }

    @Test
    public void test_crypto_sign_detached() {
        byte[] message = new byte[MESSAGE_SIZE];
        byte[] signature = new byte[Sodium.crypto_sign_BYTES];
        byte[] publicKey = new byte[Sodium.crypto_sign_PUBLICKEYBYTES];
        byte[] secretKey = new byte[Sodium.crypto_sign_SECRETKEYBYTES];

        Sodium.randombytes_buf(message);

        assertTrue(Sodium.crypto_sign_keypair(publicKey, secretKey) == 0);
        assertTrue(Sodium.crypto_sign_detached(signature, message, secretKey) >= 0);
        assertTrue(Sodium.crypto_sign_verify_detached(signature, message, publicKey) >= 0);

        signature[0] = (byte) (signature[0] ^ 1);

        assertFalse(Sodium.crypto_sign_verify_detached(signature, message, publicKey) >= 0);
    }
}
