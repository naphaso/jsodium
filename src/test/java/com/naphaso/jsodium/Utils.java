package com.naphaso.jsodium;

/**
 * Created by wolong on 22/07/16.
 */
public class Utils {
    private static final char[] HEX_DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public static byte[] decode(String hex) {
        return decodeHexString(hex);
    }

    public static String encode(byte[] hex) {
        return encodeHexString(hex);
    }

    private static byte[] decodeHexString(String string) {
        char[] data = string.toCharArray();
        int len = data.length;

        if ((len & 0x01) != 0) {
            return null;
        }


        byte[] out = new byte[len >> 1];

        for (int i = 0, j = 0; j < len; i++) {
            int f = Character.digit(data[j], 16) << 4;
            j++;
            f = f | Character.digit(data[j], 16);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    private static String encodeHexString(byte[] data) {
        return encodeHexString(data, 0, data.length);
    }

    private static String encodeHexString(byte[] data, int offset, int length) {
        char[] out = new char[length << 1];
        for (int i = 0, j = 0; i < length; i++) {
            out[j++] = HEX_DIGITS[(0xF0 & data[offset + i]) >>> 4];
            out[j++] = HEX_DIGITS[0x0F & data[offset + i]];
        }
        return new String(out);
    }
}
