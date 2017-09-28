package org.funsec.util;

public final class Bytes {

    public static final String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for (byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    /**
     * https://docs.oracle.com/javase/7/docs/api/java/io/DataOutput.html
     *
     * @param v
     */
    public static byte[] longToBytes(long v) {
        return new byte[]{(byte) (0xff & (v >> 56)),
                (byte) (0xff & (v >> 48)),
                (byte) (0xff & (v >> 40)),
                (byte) (0xff & (v >> 32)),
                (byte) (0xff & (v >> 24)),
                (byte) (0xff & (v >> 16)),
                (byte) (0xff & (v >> 8)),
                (byte) (0xff & v)};
    }

}
