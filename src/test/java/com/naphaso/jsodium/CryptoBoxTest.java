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

    @Test
    public void test_crypto_box_detached() {
        byte[] alicePrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] alicePublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
        byte[] bobPrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] bobPublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];

        byte[] nonce = new byte[Sodium.crypto_box_NONCEBYTES];

        byte[] plaintext1 = new byte[PLAINTEXT_SIZE];
        byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
        byte[] ciphertext = new byte[PLAINTEXT_SIZE];
        byte[] mac = new byte[Sodium.crypto_box_MACBYTES];

        Sodium.randombytes_buf(plaintext1);
        Sodium.randombytes_buf(nonce);

        assertEquals(Sodium.crypto_box_keypair(alicePrivateKey, alicePublicKey), 0);
        assertEquals(Sodium.crypto_box_keypair(bobPrivateKey, bobPublicKey), 0);

        assertEquals(Sodium.crypto_box_detached(ciphertext, mac, plaintext1, nonce, bobPublicKey, alicePrivateKey), 0);
        assertEquals(Sodium.crypto_box_open_detached(plaintext2, ciphertext, mac, nonce, alicePublicKey, bobPrivateKey), 0);

        assertEquals(Utils.encode(plaintext1), Utils.encode(plaintext2));
    }

    @Test
    public void test_crypto_box_seed_keypair() {
        byte[] alicePrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] alicePublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
        byte[] bobPrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] bobPublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];

        byte[] seed = new byte[Sodium.crypto_box_SEEDBYTES];

        Sodium.randombytes_buf(seed);

        assertEquals(Sodium.crypto_box_seed_keypair(alicePrivateKey, alicePublicKey, seed), 0);
        assertEquals(Sodium.crypto_box_seed_keypair(bobPrivateKey, bobPublicKey, seed), 0);

        assertEquals(Utils.encode(alicePublicKey), Utils.encode(bobPublicKey));
        assertEquals(Utils.encode(alicePrivateKey), Utils.encode(bobPrivateKey));
    }

    @Test
    public void test_crypto_box_seal() {
        byte[] alicePrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] alicePublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];

        byte[] plaintext1 = new byte[PLAINTEXT_SIZE];
        byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
        byte[] ciphertext = new byte[PLAINTEXT_SIZE + Sodium.crypto_box_SEALBYTES];

        Sodium.randombytes_buf(plaintext1);

        assertEquals(Sodium.crypto_box_keypair(alicePrivateKey, alicePublicKey), 0);

        assertEquals(Sodium.crypto_box_seal(ciphertext, plaintext1, alicePublicKey), 0);
        assertEquals(Sodium.crypto_box_seal_open(plaintext2, ciphertext, alicePublicKey, alicePrivateKey), 0);

        assertEquals(Utils.encode(plaintext1), Utils.encode(plaintext2));
    }

    @Test
    public void test_crypto_box_easy_afternm() {
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

        byte[] alicePrecomputeKey = new byte[Sodium.crypto_box_BEFORENMBYTES];
        byte[] bobPrecomputeKey = new byte[Sodium.crypto_box_BEFORENMBYTES];

        assertEquals(Sodium.crypto_box_beforenm(alicePrecomputeKey, bobPublicKey, alicePrivateKey), 0);
        assertEquals(Sodium.crypto_box_beforenm(bobPrecomputeKey, alicePublicKey, bobPrivateKey), 0);

        assertEquals(Sodium.crypto_box_easy_afternm(ciphertext, plaintext1, nonce, alicePrecomputeKey), 0);
        assertEquals(Sodium.crypto_box_open_easy_afternm(plaintext2, ciphertext, nonce, bobPrecomputeKey), 0);

        assertEquals(Utils.encode(plaintext1), Utils.encode(plaintext2));
    }

    @Test
    public void test_crypto_box_detached_afternm() {
        byte[] alicePrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] alicePublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];
        byte[] bobPrivateKey = new byte[Sodium.crypto_box_SECRETKEYBYTES];
        byte[] bobPublicKey = new byte[Sodium.crypto_box_PUBLICKEYBYTES];

        byte[] nonce = new byte[Sodium.crypto_box_NONCEBYTES];

        byte[] plaintext1 = new byte[PLAINTEXT_SIZE];
        byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
        byte[] ciphertext = new byte[PLAINTEXT_SIZE];
        byte[] mac = new byte[Sodium.crypto_box_MACBYTES];

        Sodium.randombytes_buf(plaintext1);
        Sodium.randombytes_buf(nonce);

        assertEquals(Sodium.crypto_box_keypair(alicePrivateKey, alicePublicKey), 0);
        assertEquals(Sodium.crypto_box_keypair(bobPrivateKey, bobPublicKey), 0);

        byte[] alicePrecomputeKey = new byte[Sodium.crypto_box_BEFORENMBYTES];
        byte[] bobPrecomputeKey = new byte[Sodium.crypto_box_BEFORENMBYTES];

        assertEquals(Sodium.crypto_box_beforenm(alicePrecomputeKey, bobPublicKey, alicePrivateKey), 0);
        assertEquals(Sodium.crypto_box_beforenm(bobPrecomputeKey, alicePublicKey, bobPrivateKey), 0);

        assertEquals(Sodium.crypto_box_detached_afternm(ciphertext, mac, plaintext1, nonce, alicePrecomputeKey), 0);
        assertEquals(Sodium.crypto_box_open_detached_afternm(plaintext2, ciphertext, mac, nonce, bobPrecomputeKey), 0);

        assertEquals(Utils.encode(plaintext1), Utils.encode(plaintext2));
    }
    @Test
    public void test_crypto_secretbox_easy() {

          byte[] nonce = new byte[Sodium.crypto_box_NONCEBYTES];
          byte[] plaintext1 = new byte[PLAINTEXT_SIZE];
          byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
          byte[] ciphertext = new byte[PLAINTEXT_SIZE + Sodium.crypto_box_MACBYTES];
          byte[] sharedKey = new byte[Sodium.crypto_secretbox_KEYBYTES];

          Sodium.randombytes_buf(plaintext1);
          Sodium.randombytes_buf(nonce);
          Sodium.randombytes_buf(sharedKey);
          
          assertEquals(Sodium.crypto_secretbox_easy(ciphertext, plaintext1, nonce, sharedKey), 0);
          assertEquals(Sodium.crypto_secretbox_open_easy(plaintext2, ciphertext, nonce, sharedKey), 0);
          assertEquals(Utils.encode(plaintext1), Utils.encode(plaintext2));
	}
}
