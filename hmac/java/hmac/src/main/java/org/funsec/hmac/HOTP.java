package org.funsec.hmac;

import org.funsec.util.Bytes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.function.LongSupplier;

/**
 * Generate HOTP and TOTP values based on:
 * RFC: https://www.ietf.org/rfc/rfc4226.txt
 * RFC: https://tools.ietf.org/html/rfc6238
 * https://docs.oracle.com/javase/7/docs/api/javax/crypto/Mac.html
 * <p/>
 * Modifications:<br/>
 * Moving factor or Counter is always a 32bit Java int value even if the reference implementation uses a long.<br/>
 * The return value of otp is 32bit Java int and not a String, padding for display of the digits is not part of the <br/>
 * algorithm and its more important to stress with types that the output value is always 32bits, no matter what digits were given.<br/>
 * <p/>
 * Digit size: Digits is by default 6, and can only be 0 ... 8 inclusively.
 * truncationOffset: The truncation offset by default is 0, if larger than 15, dyanamic truncation is used.<br/>
 */
public abstract class HOTP {


    /**
     * Every implementation of the Java platform is required to support SHA1
     */
    public static final String SHA_1 = "HmacSHA1";

    /**
     * Every implementation of the Java platform is required to support SHA256
     */
    public static final String SHA_256 = "HmacSHA256";

    /**
     * All Java platforms are not required to implement HmacSHA512
     */
    public static final String SHA_512 = "HmacSHA512";


    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    /**
     * Calculate the one time password value from the HOTP implementation.
     */
    public abstract int calcOtp(byte[] secret) throws InvalidKeyException, NoSuchAlgorithmException;

    /**
     * Return a new unix time based one time password with,
     *
     * X=30, Digit = 6, truncationOffset = 0
     *
     */
    public static HOTP newTOTPInstance(String shaAlgo) {
        return newTOTPInstance(shaAlgo, 6, () -> Instant.now().getEpochSecond(), 30);
    }

    public static HOTP newTOTPInstance(String shaAlgo, int digits, LongSupplier seconds, int timeStep) {
        return new TOTP(shaAlgo, digits, seconds, timeStep, -1);
    }

    public static final int otp(byte[] k, long counter, int digit) throws NoSuchAlgorithmException, InvalidKeyException {
        return otp(k, counter, digit, SHA_1, 0);
    }

    public static final int otp(byte[] k, long counter, int digit, String hsAlgo, int truncationOffset) throws NoSuchAlgorithmException, InvalidKeyException {
        return truncate(hash(k, counter, hsAlgo), digit, truncationOffset);
    }

    protected static byte[] hash(byte[] k, long counter, String hsAlgo) throws NoSuchAlgorithmException, InvalidKeyException {
        /**
         * Google authenticator
         *  static String getCheckCode(String secret) throws GeneralSecurityException,
         DecodingException {
         final byte[] keyBytes = Base32String.decode(secret);
         Mac mac = Mac.getInstance("HMACSHA1");
         mac.init(new SecretKeySpec(keyBytes, ""));
         PasscodeGenerator pcg = new PasscodeGenerator(mac);
         return pcg.generateResponseCode(0L);
         }
         */

        Mac mac = Mac.getInstance(hsAlgo);
        mac.init(new SecretKeySpec(k, "RAW"));

        return mac.doFinal(Bytes.longToBytes(counter));
    }

    protected static int truncate(byte[] hs, int digit, int truncationOffset) {
        assert digit > -1 && digit < DIGITS_POWER.length;

        int sNum = dynamicTruncation(hs, truncationOffset);

        return sNum % DIGITS_POWER[digit];
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

        //see https://docs.oracle.com/javase/7/docs/api/java/io/DataInput.html
        return binary;
    }

    /**
     * Wrapper for the TOTP implementation of HOTP
     */
    private static class TOTP extends HOTP {

        private final String shaAlgo;
        private final int truncationOffset;

        private final LongSupplier seconds;
        private final int timeStep;

        private final int digits;

        public TOTP(String shaAlgo, int digits, LongSupplier seconds, int timeStep, int truncationOffset) {
            this.shaAlgo = shaAlgo;
            this.digits = digits;
            this.truncationOffset = truncationOffset;
            this.seconds = seconds;
            this.timeStep = timeStep;
        }

        @Override
        public int calcOtp(byte[] secret) throws InvalidKeyException, NoSuchAlgorithmException {
            return otp(secret,
                    Math.floorDiv(seconds.getAsLong(), timeStep),
                    digits,
                    shaAlgo,
                    truncationOffset);
        }
    }
}
