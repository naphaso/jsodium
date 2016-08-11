package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 10/08/16.
 */
public class CryptoBoxTest extends TestCase {
    public static int PLAINTEXT_SIZE = 4000;

    @Test
    public void test_crypto_box_easy() {
        byte[] alicePrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] alicePublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
        byte[] bobPrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] bobPublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];

        byte[] nonce = new byte[Sodium.crypto_box_NONCEBYTES];

        byte[] plaintext1 = new byte[PLAINTEXT_SIZE];
        byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
        byte[] ciphertext = new byte[PLAINTEXT_SIZE + Sodium.crypto_box_MACBYTES];

        Sodium.randombytes_buf(plaintext1);
        Sodium.randombytes_buf(nonce);

        assertEquals(Sodium.crypto_box_keypair(alicePrivateKey, alicePublicKey), 0);
        assertEquals(Sodium.crypto_box_keypair(bobPrivateKey, bobPublicKey), 0);

        assertEquals(Sodium.crypto_box_easy(ciphertext, plaintext1, nonce, bobPublicKey, alicePrivateKey), 0);
        assertEquals(Sodium.crypto_box_open_easy(plaintext2, ciphertext, nonce, alicePublicKey, bobPrivateKey), 0);

        assertEquals(Utils.encode(plaintext1), Utils.encode(plaintext2));
    }

}
