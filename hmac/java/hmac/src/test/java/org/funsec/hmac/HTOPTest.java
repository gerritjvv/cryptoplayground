package org.funsec.hmac;

import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

public class HTOPTest {

    private static final Object[][] TEST_DATA_SHA1_HASHES =
            {
                    //details for each count, the intermediate HMAC value.
                    // Count    Hexadecimal HMAC-SHA-1(secret, count)
                    {0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"},
                    {1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab"},
                    {2, "0bacb7fa082fef30782211938bc1c5e70416ff44"},
                    {3, "66c28227d03a2d5529262ff016a1e6ef76557ece"},
                    {4, "a904c900a64b35909874b33e61c5938a8e15ed1c"},
                    {5, "a37e783d7b7233c083d4f62926c7a25f238d0316"},
                    {6, "bc9cd28561042c83f219324d3c607256c03272ae"},
                    {7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"},
                    {8, "1b3c89f65e6c9e883012052823443f048b4332db"},
                    {9, "1637409809a679dc698207310c8c7fc07290d9e5"}
            };

    private static final Object[][] TEST_ORIGINAL_DATA_HOTP_VALUES =
            {
                    //details for each count the truncated values (both in
                    //hexadecimal and decimal) and then the HOTP value.
                    //Count    Hexadecimal    Decimal        HOTP
                    {0, "4c93cf18", 1284755224, 755224},
                    {1, "41397eea", 1094287082, 287082},
                    {2, "82fef30", 137359152, 359152},
                    {3, "66ef7655", 1726969429, 969429},
                    {4, "61c5938a", 1640338314, 338314},
                    {5, "33c083d4", 868254676, 254676},
                    {6, "7256c032", 1918287922, 287922},
                    {7, "4e5b397", 82162583, 162583},
                    {8, "2823443f", 673399871, 399871},
                    {9, "2679dc69", 645520489, 520489}
            };

    public static final Object[][] TEST_DATA_HOTP_VALUES =
            {
                    {0, 755224},
                    {1, 717529},
                    {2, 868666},
                    {3, 23335}, //023335 != 23335
                    {4, 179456},
                    {5, 490877},
                    {6, 910469},
                    {7, 467724},
                    {8, 952310},
                    {9, 719768}
            };


    private static final byte[] secret = "12345678901234567890".getBytes();

    /**
     * This test shows that the original reference test values do not match to reference implementation.
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void refTest() throws InvalidKeyException, NoSuchAlgorithmException {
        for (int i = 0; i < TEST_DATA_SHA1_HASHES.length; i++) {
            String otp = HOTPRef.generateOTP(secret, i, 6, false, 0);
            System.out.println("REF Match otp: " + TEST_ORIGINAL_DATA_HOTP_VALUES[i][3] + " == " + otp);
        }
    }

    @Test
    public void testValues() throws InvalidKeyException, NoSuchAlgorithmException {
        for (int i = 0; i < TEST_DATA_SHA1_HASHES.length; i++) {
            assertHash(secret, i);
            assertOTP(secret, i);
        }
    }

    private void assertOTP(byte[] secret, int counter) throws NoSuchAlgorithmException, InvalidKeyException {
        int expected = (int)TEST_DATA_HOTP_VALUES[counter][1];
        int given = HOTP.otp(secret, counter);

        System.out.println("Match [" + counter + "] assertOTP: " + expected + " == " + given);

        assertEquals(expected, given);
    }

    private void assertHash(byte[] secret, int counter) throws NoSuchAlgorithmException, InvalidKeyException {
        String expected = (String) TEST_DATA_SHA1_HASHES[counter][1];
        String given = bytesToHex(HOTP.hash(secret, counter));

        System.out.println("Match hash: " + expected + " == " + given);

        assertEquals(expected, given);

    }


    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for (byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }


}
