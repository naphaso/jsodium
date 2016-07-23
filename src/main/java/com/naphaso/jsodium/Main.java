package com.naphaso.jsodium;

/**
 * Created by wolong on 21/07/16.
 */
public class Main {
    private static final char[] HEX_DIGITS =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    public static String encodeHexString(byte[] data) {
        return encodeHexString(data, 0, data.length);
    }

    public static String encodeHexString(byte[] data, int offset, int length) {
        char[] out = new char[length << 1];
        for (int i = 0, j = 0; i < length; i++) {
            out[j++] = HEX_DIGITS[(0xF0 & data[offset + i]) >>> 4];
            out[j++] = HEX_DIGITS[0x0F & data[offset + i]];
        }
        return new String(out);
    }

    public static void main(String[] args) {
        System.load("/Users/wolong/dev/naphaso.com/jsodium/src/main/java/libjsodium.dylib");
        Sodium.sodium_init();
        byte[] hash = new byte[Sodium.crypto_hash_sha256_BYTES];
        int result = Sodium.crypto_hash_sha256(hash, "hello".getBytes(), 0, "hello".getBytes().length);

        for(int i = 0; i < 5; i++) {
            System.out.print("" + "hello".getBytes()[i] + ", ");
        }

        System.out.println();

        for(int i = 0; i < hash.length; i++) {
            System.out.print("" + hash[i] + ", ");
        }

        System.out.println();
    }
}
