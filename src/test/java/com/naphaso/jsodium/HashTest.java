package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 20/07/16.
 */
public class HashTest extends TestCase {
    private static final String DATA = "hello";
    private static final String DATA_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    private static final String DATA_SHA512 = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
    private static final String DATA_SHA256_2 = "0a86050fb37a4def36885da9557f5b22a9e191767a80e7a4a2415410a4462b68";
    private static final String DATA_SHA512_2 = "c1d215a922ad186acbe436e6e2c513128b0aaa23ed6e3a4d48140b4931895384bc5b8074b7ef6b1a3e2a65b5be0c875871fec6e1a38f9c3df35c208abd4e16f2";

    @Test
    public void test_crypto_hash_sha256() {
        byte[] in = DATA.getBytes();
        byte[] out = new byte[Sodium.crypto_hash_sha256_BYTES];
        Sodium.crypto_hash_sha256(out, in, 0, in.length);
        assertEquals(DATA_SHA256, Utils.encode(out));
    }

    @Test
    public void test_crypto_hash_sha256_state_1() {
        byte[] in = DATA.getBytes();
        byte[] out = new byte[Sodium.crypto_hash_sha256_BYTES];
        byte[] state = new byte[Sodium.crypto_hash_sha256_statebytes()];
        Sodium.crypto_hash_sha256_init(state);
        Sodium.crypto_hash_sha256_update(state, in, 0, in.length);
        Sodium.crypto_hash_sha256_final(state, out);
        assertEquals(DATA_SHA256, Utils.encode(out));
    }


    @Test
    public void test_crypto_hash_sha256_state_2() {
        byte[] in = DATA.getBytes();
        byte[] out = new byte[Sodium.crypto_hash_sha256_BYTES];
        byte[] state = new byte[Sodium.crypto_hash_sha256_statebytes()];
        Sodium.crypto_hash_sha256_init(state);
        Sodium.crypto_hash_sha256_update(state, in, 0, in.length);
        Sodium.crypto_hash_sha256_update(state, in, 0, in.length);
        Sodium.crypto_hash_sha256_final(state, out);
        assertEquals(DATA_SHA256_2, Utils.encode(out));
    }

    @Test
    public void test_crypto_hash_sha512() {
        byte[] in = DATA.getBytes();
        byte[] out = new byte[Sodium.crypto_hash_sha512_BYTES];
        Sodium.crypto_hash_sha512(out, in, 0, in.length);
        assertEquals(DATA_SHA512, Utils.encode(out));
    }


    @Test
    public void test_crypto_hash_sha512_state_1() {
        byte[] in = DATA.getBytes();
        byte[] out = new byte[Sodium.crypto_hash_sha512_BYTES];
        byte[] state = new byte[Sodium.crypto_hash_sha512_statebytes()];
        Sodium.crypto_hash_sha512_init(state);
        Sodium.crypto_hash_sha512_update(state, in, 0, in.length);
        Sodium.crypto_hash_sha512_final(state, out);
        assertEquals(DATA_SHA512, Utils.encode(out));
    }

    @Test
    public void test_crypto_hash_sha512_state_2() {
        byte[] in = DATA.getBytes();
        byte[] out = new byte[Sodium.crypto_hash_sha512_BYTES];
        byte[] state = new byte[Sodium.crypto_hash_sha512_statebytes()];
        Sodium.crypto_hash_sha512_init(state);
        Sodium.crypto_hash_sha512_update(state, in, 0, in.length);
        Sodium.crypto_hash_sha512_update(state, in, 0, in.length);
        Sodium.crypto_hash_sha512_final(state, out);
        assertEquals(DATA_SHA512_2, Utils.encode(out));
    }

    @Test
    public void test_crypto_hash() {
        byte[] in = DATA.getBytes();
        byte[] out = new byte[Sodium.crypto_hash_BYTES];
        Sodium.crypto_hash(out, in, 0, in.length);
        assertEquals(DATA_SHA512, Utils.encode(out));
    }
}
