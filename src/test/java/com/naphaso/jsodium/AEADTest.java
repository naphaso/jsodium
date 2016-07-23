package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 22/07/16.
 */
public class AEADTest extends TestCase {
    public static final int PLAINTEXT_SIZE = 4000;
    public static final int ADDITIONAL_DATA_SIZE = 4000;

    @Test
    public void test_crypto_aead_aes256gcm_is_available() {
        Sodium.crypto_aead_aes256gcm_is_available();
    }

    @Test
    public void test_crypto_aead_aes256gcm() {
        if(Sodium.crypto_aead_aes256gcm_is_available() == 0) {
            return;
        }

        byte[] nonce = new byte[Sodium.crypto_aead_aes256gcm_NPUBBYTES];
        byte[] key = new byte[Sodium.crypto_aead_aes256gcm_KEYBYTES];
        byte[] plaintext = new byte[PLAINTEXT_SIZE];
        byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
        byte[] additionalData = new byte[ADDITIONAL_DATA_SIZE];
        byte[] ciphertext = new byte[PLAINTEXT_SIZE + Sodium.crypto_aead_aes256gcm_ABYTES];

        Sodium.randombytes_buf(nonce);
        Sodium.randombytes_buf(key);
        Sodium.randombytes_buf(plaintext);
        Sodium.randombytes_buf(additionalData);

        // encrypt
        int ciphertextSize = Sodium.crypto_aead_aes256gcm_encrypt(ciphertext, plaintext, additionalData, nonce, key);
        assertTrue(ciphertextSize > 0);
        byte[] ciphertextActual = new byte[ciphertextSize];
        System.arraycopy(ciphertext, 0, ciphertextActual, 0, ciphertextSize);

        // decrypt
        int plaintextSize = Sodium.crypto_aead_aes256gcm_decrypt(plaintext2, ciphertextActual, additionalData, nonce, key);
        assertTrue(plaintextSize > 0);
        byte[] plaintext2Actual = new byte[plaintextSize];
        System.arraycopy(plaintext2, 0, plaintext2Actual, 0, plaintextSize);

        assertEquals(Utils.encode(plaintext), Utils.encode(plaintext2Actual));
    }

    @Test
    public void test_crypto_aead_chacha20poly1305() {
        byte[] nonce = new byte[Sodium.crypto_aead_chacha20poly1305_NPUBBYTES];
        byte[] key = new byte[Sodium.crypto_aead_chacha20poly1305_KEYBYTES];
        byte[] plaintext = new byte[PLAINTEXT_SIZE];
        byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
        byte[] additionalData = new byte[ADDITIONAL_DATA_SIZE];
        byte[] ciphertext = new byte[PLAINTEXT_SIZE + Sodium.crypto_aead_chacha20poly1305_ABYTES];

        Sodium.randombytes_buf(nonce);
        Sodium.randombytes_buf(key);
        Sodium.randombytes_buf(plaintext);
        Sodium.randombytes_buf(additionalData);

        // encrypt
        int ciphertextSize = Sodium.crypto_aead_chacha20poly1305_encrypt(ciphertext, plaintext, additionalData, nonce, key);
        assertTrue(ciphertextSize > 0);
        byte[] ciphertextActual = new byte[ciphertextSize];
        System.arraycopy(ciphertext, 0, ciphertextActual, 0, ciphertextSize);

        // decrypt
        int plaintextSize = Sodium.crypto_aead_chacha20poly1305_decrypt(plaintext2, ciphertextActual, additionalData, nonce, key);
        assertTrue(plaintextSize > 0);
        byte[] plaintext2Actual = new byte[plaintextSize];
        System.arraycopy(plaintext2, 0, plaintext2Actual, 0, plaintextSize);

        assertEquals(Utils.encode(plaintext), Utils.encode(plaintext2Actual));
    }

    @Test
    public void test_crypto_aead_chacha20poly1305_ietf() {
        byte[] nonce = new byte[Sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        byte[] key = new byte[Sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES];
        byte[] plaintext = new byte[PLAINTEXT_SIZE];
        byte[] plaintext2 = new byte[PLAINTEXT_SIZE];
        byte[] additionalData = new byte[ADDITIONAL_DATA_SIZE];
        byte[] ciphertext = new byte[PLAINTEXT_SIZE + Sodium.crypto_aead_chacha20poly1305_ietf_ABYTES];

        Sodium.randombytes_buf(nonce);
        Sodium.randombytes_buf(key);
        Sodium.randombytes_buf(plaintext);
        Sodium.randombytes_buf(additionalData);

        // encrypt
        int ciphertextSize = Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, plaintext, additionalData, nonce, key);
        assertTrue(ciphertextSize > 0);
        byte[] ciphertextActual = new byte[ciphertextSize];
        System.arraycopy(ciphertext, 0, ciphertextActual, 0, ciphertextSize);

        // decrypt
        int plaintextSize = Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(plaintext2, ciphertextActual, additionalData, nonce, key);
        assertTrue(plaintextSize > 0);
        byte[] plaintext2Actual = new byte[plaintextSize];
        System.arraycopy(plaintext2, 0, plaintext2Actual, 0, plaintextSize);

        assertEquals(Utils.encode(plaintext), Utils.encode(plaintext2Actual));
    }
}
