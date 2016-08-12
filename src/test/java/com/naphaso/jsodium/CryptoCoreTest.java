package com.naphaso.jsodium;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Created by wolong on 11/08/16.
 */
public class CryptoCoreTest extends TestCase {

    @Test
    public void test_crypto_core_hsalsa20() {
        byte[] in = new byte[Sodium.crypto_core_hsalsa20_INPUTBYTES];
        byte[] out = new byte[Sodium.crypto_core_hsalsa20_OUTPUTBYTES];
        byte[] out_expected = new byte[]{
                (byte) 0x1b, (byte) 0x27, (byte) 0x55, (byte) 0x64, (byte) 0x73, (byte) 0xe9, (byte) 0x85, (byte) 0xd4,
                (byte) 0x62, (byte) 0xcd, (byte) 0x51, (byte) 0x19, (byte) 0x7a, (byte) 0x9a, (byte) 0x46, (byte) 0xc7,
                (byte) 0x60, (byte) 0x09, (byte) 0x54, (byte) 0x9e, (byte) 0xac, (byte) 0x64, (byte) 0x74, (byte) 0xf2,
                (byte) 0x06, (byte) 0xc4, (byte) 0xee, (byte) 0x08, (byte) 0x44, (byte) 0xf6, (byte) 0x83, (byte) 0x89
        };
        byte[] key = new byte[]{
                (byte) 0x4a, (byte) 0x5d, (byte) 0x9d, (byte) 0x5b, (byte) 0xa4, (byte) 0xce, (byte) 0x2d, (byte) 0xe1, (byte) 0x72, (byte) 0x8e, (byte) 0x3b,
                (byte) 0xf4, (byte) 0x80, (byte) 0x35, (byte) 0x0f, (byte) 0x25, (byte) 0xe0, (byte) 0x7e, (byte) 0x21, (byte) 0xc9, (byte) 0x47, (byte) 0xd1,
                (byte) 0x9e, (byte) 0x33, (byte) 0x76, (byte) 0xf0, (byte) 0x9b, (byte) 0x3c, (byte) 0x1e, (byte) 0x16, (byte) 0x17, (byte) 0x42
        };
        byte[] constb = new byte[]{
                (byte) 0x65, (byte) 0x78, (byte) 0x70, (byte) 0x61, (byte) 0x6e, (byte) 0x64, (byte) 0x20, (byte) 0x33,
                (byte) 0x32, (byte) 0x2d, (byte) 0x62, (byte) 0x79, (byte) 0x74, (byte) 0x65, (byte) 0x20, (byte) 0x6b
        };

        assertEquals(Sodium.crypto_core_hsalsa20(out, in, key, constb), 0);
        assertEquals(Utils.encode(out_expected), Utils.encode(out));
    }


    @Test
    public void test_crypto_core_hchacha20() {
        // TODO: add test vectors for hchacha20

        byte[] in = new byte[Sodium.crypto_core_hchacha20_INPUTBYTES];
        byte[] out = new byte[Sodium.crypto_core_hchacha20_OUTPUTBYTES];
        byte[] key = new byte[Sodium.crypto_core_hchacha20_KEYBYTES];
        byte[] constb = new byte[Sodium.crypto_core_hchacha20_CONSTBYTES];

        assertEquals(Sodium.crypto_core_hchacha20(out, in, key, constb), 0);
    }

    @Test
    public void test_crypto_core_salsa20() {
        byte[] in = new byte[]{
                (byte) 101, (byte) 102, (byte) 103, (byte) 104, (byte) 105, (byte) 106, (byte) 107, (byte) 108,
                (byte) 109, (byte) 110, (byte) 111, (byte) 112, (byte) 113, (byte) 114, (byte) 115, (byte) 116
        };
        byte[] out = new byte[Sodium.crypto_core_salsa20_OUTPUTBYTES];
        byte[] out_expected = new byte[]{
                (byte) 69, (byte) 37, (byte) 68, (byte) 39, (byte) 41, (byte) 15, (byte) 107, (byte) 193,
                (byte) 255, (byte) 139, (byte) 122, (byte) 6, (byte) 170, (byte) 233, (byte) 217, (byte) 98,
                (byte) 89, (byte) 144, (byte) 182, (byte) 106, (byte) 21, (byte) 51, (byte) 200, (byte) 65,
                (byte) 239, (byte) 49, (byte) 222, (byte) 34, (byte) 215, (byte) 114, (byte) 40, (byte) 126,
                (byte) 104, (byte) 197, (byte) 7, (byte) 225, (byte) 197, (byte) 153, (byte) 31, (byte) 2,
                (byte) 102, (byte) 78, (byte) 76, (byte) 176, (byte) 84, (byte) 245, (byte) 246, (byte) 184,
                (byte) 177, (byte) 160, (byte) 133, (byte) 130, (byte) 6, (byte) 72, (byte) 149, (byte) 119,
                (byte) 192, (byte) 195, (byte) 132, (byte) 236, (byte) 234, (byte) 103, (byte) 246, (byte) 74
        };
        byte[] key = new byte[]{
                (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6, (byte) 7, (byte) 8, (byte) 9, (byte) 10, (byte) 11,
                (byte) 12, (byte) 13, (byte) 14, (byte) 15, (byte) 16, (byte) 201, (byte) 202, (byte) 203, (byte) 204, (byte) 205, (byte) 206,
                (byte) 207, (byte) 208, (byte) 209, (byte) 210, (byte) 211, (byte) 212, (byte) 213, (byte) 214, (byte) 215, (byte) 216
        };
        byte[] constb = new byte[]{
                (byte) 101, (byte) 120, (byte) 112, (byte) 97, (byte) 110, (byte) 100, (byte) 32, (byte) 51,
                (byte) 50, (byte) 45, (byte) 98, (byte) 121, (byte) 116, (byte) 101, (byte) 32, (byte) 107
        };

        assertEquals(Sodium.crypto_core_salsa20(out, in, key, constb), 0);
        assertEquals(Utils.encode(out_expected), Utils.encode(out));
    }

    @Test
    public void test_crypto_core_salsa2012() {
        // TODO: add test vectors for salsa2012

        byte[] in = new byte[Sodium.crypto_core_salsa2012_INPUTBYTES];
        byte[] out = new byte[Sodium.crypto_core_salsa2012_OUTPUTBYTES];
        byte[] key = new byte[Sodium.crypto_core_salsa2012_KEYBYTES];
        byte[] constb = new byte[Sodium.crypto_core_salsa2012_CONSTBYTES];

        assertEquals(Sodium.crypto_core_salsa2012(out, in, key, constb), 0);
    }

    @Test
    public void test_crypto_core_salsa208() {
        // TODO: add test vectors for salsa208

        byte[] in = new byte[Sodium.crypto_core_salsa208_INPUTBYTES];
        byte[] out = new byte[Sodium.crypto_core_salsa208_OUTPUTBYTES];
        byte[] key = new byte[Sodium.crypto_core_salsa208_KEYBYTES];
        byte[] constb = new byte[Sodium.crypto_core_salsa208_CONSTBYTES];

        assertEquals(Sodium.crypto_core_salsa208(out, in, key, constb), 0);
    }
}
