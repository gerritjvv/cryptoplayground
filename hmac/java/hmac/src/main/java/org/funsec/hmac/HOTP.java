package org.funsec.hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Generate HOTP values based on:
 * RFC: https://www.ietf.org/rfc/rfc4226.txt
 * https://docs.oracle.com/javase/7/docs/api/javax/crypto/Mac.html
 */
public class HOTP {

    public static final String SHA_1 = "HmacSHA1";

    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    public static final int otp(byte[] k, long counter) throws NoSuchAlgorithmException, InvalidKeyException {
        return otp(k, counter, 6);
    }

    public static final int otp(byte[] k, long counter, int digit) throws NoSuchAlgorithmException, InvalidKeyException {
        return otp(k, counter, digit, SHA_1, 0);
    }

    public static final int otp(byte[] k, long counter, int digit, String hsAlgo, int truncationOffset) throws NoSuchAlgorithmException, InvalidKeyException {
        return truncate(hash(k, counter, hsAlgo), digit, truncationOffset);
    }

    protected static byte[] hash(byte[] k, long counter) throws NoSuchAlgorithmException, InvalidKeyException {
        return hash(k, counter, SHA_1);
    }

    protected static byte[] hash(byte[] k, long counter, String hsAlgo) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(hsAlgo);
        mac.init(new SecretKeySpec(k, "RAW"));

        return mac.doFinal(longToBytes(counter));
    }

    protected static int truncate(byte[] hs, int digit, int truncationOffset) {

        int sNum = dynamicTruncation(hs, truncationOffset);

        return sNum % DIGITS_POWER[digit];
    }

    static public String generateOTP(byte[] secret,
                                     long movingFactor,
                                     int codeDigits,
                                     boolean addChecksum,
                                     int truncationOffset)
            throws NoSuchAlgorithmException, InvalidKeyException
    {
        // put movingFactor value into text byte array
        String result = null;
        int digits = codeDigits;

        // compute hmac hash
        byte[] hash = hash(secret, movingFactor);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        if ( (0<=truncationOffset) &&
                (truncationOffset<(hash.length-4)) ) {
            offset = truncationOffset;
        }
        int binary =
                ((hash[offset] & 0x7f) << 24)
                        | ((hash[offset + 1] & 0xff) << 16)
                        | ((hash[offset + 2] & 0xff) << 8)

            | (hash[offset + 3] & 0xff);

        System.out.println("REF: offset " + offset + " binary " + binary + " counter " + movingFactor);

        int otp = binary % DIGITS_POWER[codeDigits];
        System.out.println("REF: otp: " + otp);
        result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }

    /**
     * Changes from the original reference implementation:
     */
    protected static int dynamicTruncation(byte[] hs, int truncationOffset) {
        int offset;

        if (0 <= truncationOffset &&
                truncationOffset <= hs.length - 4) {
            offset = truncationOffset;
        } else {
            offset = hs[hs.length - 1] & 0xF; //lower 4bits of hs[19]
        }

        int binary = ((hs[offset] & 0x7F) << 24) |
                ((hs[offset + 1] & 0xFF) << 16) |
                ((hs[offset + 2] & 0xFF) << 8) |
                (hs[offset + 3] & 0xFF);

        System.out.println("Custom offset: " + offset + " binary " + binary);

        //see https://docs.oracle.com/javase/7/docs/api/java/io/DataInput.html
        return binary;
    }

    /**
     * https://docs.oracle.com/javase/7/docs/api/java/io/DataOutput.html
     *
     * @param v
     */
    private static byte[] longToBytes(long v) {
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
