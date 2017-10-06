package org.funsec;

import org.apache.commons.codec.binary.Base32;
import org.funsec.hmac.HOTP;
import org.funsec.util.Permutations;
import org.funsec.util.Utils;

import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.IntStream;

import static org.funsec.OTPToken.matchWithStolen;
import static org.funsec.util.Utils.asCharStr;

/**
 *
 * Google Authenticator forces keys to be in Base32 which limits the keyspace to 32letters only.
 *
 * 16, 26 or 32 character strings are presented by providers to the google auth app.
 *
 * 7777777777777777 => 16  => 10bytes => combinations 32^16 ==> 1208925819614629000000000/2000000000
 * 77777777777777777777777777 => 26 => 16 bytes
 * 77777777777777777777777777777777 => 32 => 20 bytes
 *
 * 10 bytes == 80 bits => 2^80
 *
 */
public class GoogleTOTP
{

    public static final byte[] ENCODE_TABLE = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            '2', '3', '4', '5', '6', '7',
    };

    public static void main( String[] args ) throws InterruptedException {

        String shaAlgo = HOTP.SHA_1;

        int keyLen = 16;

        //---- any random key to simulate if in the search section we can get to this again.
        OTPToken[] stolenTokens = OTPToken.stealOTP(keyLen, ENCODE_TABLE, 10, shaAlgo, true);
        OTPToken firstToken = stolenTokens[0];

        int stolenKeyLen = firstToken.getKey().length; // This knowledge needs to be known also, i.e we need to know if a certain provider give keys that after base32.decode have 10 byte length.

        System.out.println("Selected random key: " + Arrays.toString(firstToken.getKey()) + " ( " + asCharStr(firstToken.getKey()) + ") ==> " + firstToken.getOtp());

        OTPToken.printOtpValues(stolenTokens, firstToken.getKey(), shaAlgo);

        //----- search

        AtomicReference<byte[]> foundMatch = new AtomicReference<>(null);
        AtomicInteger scanCount = new AtomicInteger(0);


        ExecutorService executorService = Executors.newCachedThreadPool();

        BlockingQueue<byte[]> queue = new ArrayBlockingQueue<>(1000);

        Consumer<byte[]> handler = (byte[] bts) -> {


                if(matchWithStolen(stolenTokens, bts, shaAlgo)){
                    System.out.println(">>>>>>>>>>> Found: " + Arrays.toString(bts));
                    OTPToken.printOtpValues(stolenTokens, bts, shaAlgo);
                    foundMatch.set(bts);
                }
                scanCount.incrementAndGet();

        };


        long startTime = System.currentTimeMillis();

        int searchKeyLen = 4;

        executorService.submit(() -> {
            Permutations.addAndCarry(searchKeyLen, byteRange(0, 256), handler);
        });

        executorService.shutdown();

        System.out.println("Key Len :  " + firstToken.getKey().length );
        long total = (long)Math.pow(256, searchKeyLen);

        int scanned = 0;

        while(foundMatch.get() == null && (scanned = scanCount.get()) > -1 && scanned < total) {
            Thread.sleep(10000);
            System.out.println("Scanned: " + scanned + " " + ((int)(((double)scanned/total)*100)) + "% out of " + total + " time elapsed " + (System.currentTimeMillis() - startTime)  + "ms");
        }

        long endTime = System.currentTimeMillis();

        executorService.shutdownNow();

        System.out.println("Completed in " + (endTime - startTime) + "ms");
    }

    private static byte[] byteRange(int from, int len) {
        byte[] bts = new byte[len];

        for(int i = 0; i < len; i++) {
            bts[i] = (byte)i;
        }

        return bts;
    }

}
