package org.funsec.util;

import java.security.SecureRandom;

public class Utils {

    public static String repeat(char ch, int len) {
        StringBuilder buff = new StringBuilder();
        for(int i = 0; i < len; i++) {
            buff.append(ch);
        }

        return buff.toString();
    }

    public static byte[] genRandomKey(int keyLen, byte[] encodeTable) {
        byte[] k = new byte[keyLen];

        SecureRandom random = new SecureRandom();

        for (int i = 0; i < keyLen; i++) {
            k[i] = encodeTable[random.nextInt(encodeTable.length)];
        }

        return k;
    }

    public static String asCharStr(byte[] bts) {
        StringBuilder buff = new StringBuilder(bts.length);
        for (int i = 0; i < bts.length; i++)
            buff.append((char) bts[i]);

        return buff.toString();
    }

    public static int asInt(byte[] bts, int pos) {
        return (((bts[pos] & 0xff) << 24) | ((bts[pos+1] & 0xff) << 16) |
                ((bts[pos+2] & 0xff) << 8) | (bts[pos+3] & 0xff));
    }

}
