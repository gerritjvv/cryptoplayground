package org.funsec;

import org.funsec.hmac.HOTP;
import org.funsec.util.Utils;
import org.funsec.util.Permutations;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import static org.funsec.OTPToken.matchWithStolen;
import static org.funsec.OTPToken.printOtpValues;
import static org.funsec.util.Utils.asCharStr;

/**
 * Performs a brute force attack on random generated keys which simulate stolen tokens.<br/>
 * <p/>
 *
 */
public class BruteForceOTPAttack {


    public static void main(String arg[]) throws InterruptedException {
        runAttack(8, GoogleTOTP.ENCODE_TABLE, HOTP.SHA_1);
    }

    public static void runAttack(int keyLen, byte[] alphabet, String shaAlgo) {

        long totalPermutations = (long)Math.pow(alphabet.length, keyLen);

        long start = System.currentTimeMillis();


        OTPToken[] stolenTokens = OTPToken.stealOTP(keyLen, alphabet, 10, shaAlgo);

        OTPToken firstToken = stolenTokens[0];

        System.out.println("Selected random key: " + Arrays.toString(firstToken.getKey()) + " ( " + asCharStr(firstToken.getKey()) + ") ==> " + firstToken.getOtp());


        int otp = firstToken.getOtp();

        AtomicLong counter = new AtomicLong();
        AtomicLong matchCounter = new AtomicLong();

        List<byte[]> matchedKeys = new ArrayList<>();

        Consumer<byte[]> handler = (byte[] bts) -> {

            long count = counter.getAndIncrement();

            if( count % 1000000 == 0 && count != 0) {
                System.err.println("Processed: " + count + " of " + totalPermutations);
            }



            if (matchWithStolen(stolenTokens, bts, shaAlgo)) {

                matchedKeys.add(Arrays.copyOf(bts, bts.length));
                System.out.println("Found key match: " + Arrays.toString(bts) + " (" + asCharStr(bts) + ") ==> " + otp);
                matchCounter.incrementAndGet();

                throw new RuntimeException();
            }

        };

        Permutations.addAndCarry(keyLen, GoogleTOTP.ENCODE_TABLE, handler);

        long end = System.currentTimeMillis();

        System.out.println("Searched " + counter.get() + " " + ((int)(((double)counter.get()/totalPermutations)*100)) + "% permutations in " + (end - start) + "ms found " + matchCounter.get());

        System.out.println("Printing match correlations: ");

        printOtpValues(stolenTokens, firstToken.getKey(), shaAlgo);

        System.out.println("--------------------------[Brute Force check]-------------------------------");

        for (byte[] matchedKey : matchedKeys) {
            printOtpValues(stolenTokens, matchedKey, shaAlgo);
        }


        System.out.println("--------------------------------------------------------------------");

    }



}
