package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

import java.util.Arrays;

/**
 * Created by wolong on 22/07/16.
 */
public class RandomTest extends TestCase {
    public static final int BUFFER_SIZE = 4096;

    @Test
    public void test_randombytes_buf() {
        byte[] buffer1 = new byte[BUFFER_SIZE];
        byte[] buffer2 = new byte[BUFFER_SIZE];
        Sodium.randombytes_buf(buffer1);
        Sodium.randombytes_buf(buffer1);

        assertFalse(Arrays.equals(buffer1, buffer2));
    }

    @Test
    public void test_randombytes_random() {
        Sodium.randombytes_random();
    }

    @Test
    public void test_randombytes_uniform() {
        Sodium.randombytes_uniform(1000);
    }

    @Test
    public void test_randombytes_stir() {
        Sodium.randombytes_stir();
    }

    @Test
    public void test_randombytes_close() {
        Sodium.randombytes_close();
    }
}
