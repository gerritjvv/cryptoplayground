package org.funsec.hmac;

import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Arrays;
import java.util.TimeZone;

import static org.junit.Assert.assertEquals;

public class TOTPTest {

    private static final byte[] SEED = "12345678901234567890".getBytes();

    private static final byte[] SEED32 = "12345678901234567890123456789012".getBytes();

    private static final byte[] SEED64 = "1234567890123456789012345678901234567890123456789012345678901234".getBytes();

    private static final Object[][] TOTP_TEST_VALUES = new Object[][]
            {
                    /*
                      +-------------+--------------+------------------+----------+--------+
                      |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
                      +-------------+--------------+------------------+----------+--------+
                    */
                    {59, "1970-01-01 00:00:59", "0000000000000001", 94287082, HOTP.SHA_1, SEED},
                    {59, "1970-01-01 00:00:59", "0000000000000001", 46119246, HOTP.SHA_256, SEED32},
                    {59, "1970-01-01 00:00:59", "0000000000000001", 90693936, HOTP.SHA_512, SEED64},

                    {1111111109, "2005-03-18 01:58:29", "00000000023523EC", 7081804, HOTP.SHA_1, SEED},
                    {1111111109, "2005-03-18 01:58:29", "00000000023523EC", 68084774, HOTP.SHA_256, SEED32},
                    {1111111109, "2005-03-18 01:58:29", "00000000023523EC", 25091201, HOTP.SHA_512, SEED64},

                    {1111111111, "2005-03-18 01:58:31", "00000000023523ED", 14050471, HOTP.SHA_1, SEED},
                    {1111111111, "2005-03-18 01:58:31", "00000000023523ED", 67062674, HOTP.SHA_256, SEED32},
                    {1111111111, "2005-03-18 01:58:31", "00000000023523ED", 99943326, HOTP.SHA_512, SEED64},

                    {1234567890, "2009-02-13 23:31:30", "000000000273EF07", 89005924, HOTP.SHA_1, SEED},
                    {1234567890, "2009-02-13 23:31:30", "000000000273EF07", 91819424, HOTP.SHA_256, SEED32},
                    {1234567890, "2009-02-13 23:31:30", "000000000273EF07", 93441116, HOTP.SHA_512, SEED64},

                    {2000000000, "2033-05-18 03:33:20", "0000000003F940AA", 69279037, HOTP.SHA_1, SEED},
                    {2000000000, "2033-05-18 03:33:20", "0000000003F940AA", 90698825, HOTP.SHA_256, SEED32},
                    {2000000000, "2033-05-18 03:33:20", "0000000003F940AA", 38618901, HOTP.SHA_512, SEED64},

                    {20000000000L, "2603-10-11 11:33:20", "0000000027BC86AA", 65353130, HOTP.SHA_1, SEED},
                    {20000000000L, "2603-10-11 11:33:20", "0000000027BC86AA", 77737706, HOTP.SHA_256, SEED32},
                    {20000000000L, "2603-10-11 11:33:20", "0000000027BC86AA", 47863826, HOTP.SHA_512, SEED64},

            };

    @Test
    public void testTOTPRFCValues() throws InvalidKeyException, NoSuchAlgorithmException {

        for (Object[] vals : TOTP_TEST_VALUES) {
            assertTOTP(((Number) vals[0]).longValue(), (int) vals[3], (String) vals[4], (byte[])vals[5]);
        }

    }

    public void assertTOTP(long seconds, int totp, String shaAlgo, byte[] seed) throws NoSuchAlgorithmException, InvalidKeyException {

        HOTP hotp = HOTP.newTOTPInstance(shaAlgo, 8, () -> seconds, 30);

        int given = hotp.calcOtp(seed);

        System.out.println("Matching: " + seconds + " " + totp + " == " + given + " mode " + shaAlgo);
        assertEquals(totp, given);
    }

    private static long getSecondsFrom(String utcString) {
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

        try {
            return dateFormat.parse(utcString).toInstant().getEpochSecond();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }


}
