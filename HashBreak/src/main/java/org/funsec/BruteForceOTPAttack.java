package org.funsec;

import org.funsec.hmac.HOTP;
import org.funsec.util.Permutations;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.ObjIntConsumer;
import java.util.function.ObjLongConsumer;

import static org.funsec.OTPToken.matchWithStolen;
import static org.funsec.OTPToken.printOtpValues;
import static org.funsec.util.Utils.asCharStr;

/**
 * Performs a brute force attack on random generated keys which simulate stolen tokens.<br/>
 * <p/>
 */
public class BruteForceOTPAttack {


    //32^4 = 1048576

    public static void main(String arg[]) throws InterruptedException {

        ExecutorService exec = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()-2);

        int keyLen = 16;

        OTPToken[] stolenTokens = OTPToken.stealOTP(keyLen, GoogleTOTP.ENCODE_TABLE, 10, HOTP.SHA_1);

        OTPToken firstToken = stolenTokens[0];

        System.out.println("Selected random key: " + Arrays.toString(firstToken.getKey()) + " ( " + asCharStr(firstToken.getKey()) + ") ==> " + firstToken.getOtp());


        int otp = firstToken.getOtp();

        AtomicLong counter = new AtomicLong();
        AtomicLong matchCounter = new AtomicLong();

        List<byte[]> matchedKeys = new ArrayList<>();

        long start = System.currentTimeMillis();

        ObjIntConsumer<byte[]> handler = (byte[] bts, int count) -> {


            if (count % 1000000 == 0 && count != 0) {
                counter.lazySet(count);
                System.err.println("Processed: " + count + " in " + (System.currentTimeMillis() - start) + "ms");
            }


            if (matchWithStolen(stolenTokens, bts, HOTP.SHA_1)) {

                matchedKeys.add(Arrays.copyOf(bts, bts.length));
                System.out.println("Found key match: " + Arrays.toString(bts) + " (" + asCharStr(bts) + ") ==> " + otp);
                matchCounter.incrementAndGet();

                throw new RuntimeException();
            }

        };

        StringBuilder buff = new StringBuilder();
        for(int i = 0;i  < 32; i++) {
            for(int a = 0; a < 32; a++) {
                for(int b = 0; b < 32; b++) {
                    for(int c = 0; c < 32; c++) {
                        for(int d = 0; d < 32; d++) {
                            if(buff.length() != 0)
                                buff.append(',');

                            buff.append(i + ":" + a + ":" + b + ":" + c + ":" + d + ":");
                        }
                    }
                }
            }
        }

//        System.out.println(buff.toString());
//        if(true) return;

        splitAttack(exec, handler,keyLen, GoogleTOTP.ENCODE_TABLE, HOTP.SHA_1, buff.toString());

        exec.shutdown();
        exec.awaitTermination(Long.MAX_VALUE, TimeUnit.MILLISECONDS);

//        Map<String, Object> opts = TOTPApp.argumentsAsMap(arg);
//
//        int keyLen = 0;
//        if (opts.get("keylen") == null) {
//            printHelp();
//            System.exit(-1);
//        } else {
//            keyLen = Integer.parseInt(opts.get("keylen").toString());
//        }
//
//        byte[] alphabet = GoogleTOTP.ENCODE_TABLE;
//
//        if (opts.get("alphabet") != null) {
//            alphabet = opts.get("alphabet").toString().getBytes();
//        }
//
//        if (opts.get("splitinfo") != null) {
//            Permutations.printKeySpaceSplit(keyLen, GoogleTOTP.ENCODE_TABLE);
//        } else if (opts.get("alphabetsplitinfo") != null) {
//            Permutations.printAlphabetInfoSegment(keyLen, alphabet);
//        } else if (opts.get("alphabetinfo") != null) {
//            Permutations.printAlphabetInfo(keyLen, alphabet);
//        } else if (opts.get("run") != null) {
//            if (opts.get("splits") == null) {
//                runAttack(keyLen, alphabet, HOTP.SHA_1);
//            } else {
//                String splits = opts.get("splits").toString();
//
//                splitAttack(exec, keyLen, alphabet, HOTP.SHA_1, splits);
//            }
//        } else {
//            printHelp();
//            System.exit(-1);
//        }
//
//        System.exit(0);
    }

    private static void printHelp() {
        System.out.println("-keylen <keylength> -alphabet <bytestring -splits <number of splits> e.g ABC> <command>");
        System.out.println("commands: splitinfo, alphabetsplitinfo, alphabetinfo, run");
    }

    /**
     * Is part of a split attack simulation.
     * <p>
     * e.g
     * <pre>
     * indexes = 0:0,0:1,1:0,1:1 // the size of indexes is the total number of splits assigned to run on this node, here is is 4.
     *                           // note that the node can execute columns concurrently
     *                           // x1:x2:x3 form a path down the splits
     *                           // x1 => segment in sp1, x2 segment in sp2 etc..
     *                           //
     *                           // So a single path is a single segment coordinate down the splits to the last split.
     *                           //
     * splits = [ sp1, sp2 ]     // split path, sp1 is split into sp2 and so on.
     *
     * sp1.segments = 2, segment_len=200
     * sp2.segments = 2, segment_len = 50
     *
     * For 0:0 sp1.segments[0], sp2.segments[0],
     * For 0:1 sp1.segments[0], sp2.segments[1],
     * For 1:0 sp1.segments[1], sp2.segments[0],
     * For 1:1 sp1.segments[1], sp2.segments[1],
     * </pre>
     */
    private static void splitAttack(ExecutorService exec,
                                    ObjIntConsumer<byte[]> handler,
                                    int keyLen, byte[] alphabet, String shaAlgo, String splitpath) {

        List<Permutations.SegmentIndexPath> indexes = Permutations.SegmentIndexPath.parsePath(splitpath);

        List<Permutations.Split> splits = Permutations.splitKeySpace(keyLen, alphabet);

        byte[] word = new byte[splits.get(0).keyLen];

        System.out.println("Splits: " + splits);
        System.out.println("Indexes: " + indexes);

        for (Permutations.SegmentIndexPath coord : indexes) {
//            exec.submit(() -> {
//                try {
                    runSplitAttackBuild(exec, handler, word, 0, splits, coord, shaAlgo);
//                } catch (Throwable t) {
//                    t.printStackTrace();
//                }
//            });
        }
    }

    /**
     * Recursively go through each level of the split building the word constants for the attack.
     * When the lowest level is reached, the attack is started.
     *
     * @param word
     * @param lvl
     * @param splits
     * @param coord
     */
    private static void runSplitAttackBuild(ExecutorService exec,
                                            ObjIntConsumer<byte[]> handler,
                                            byte[] word, int lvl, List<Permutations.Split> splits, Permutations.SegmentIndexPath coord, String shaAlgo) {


        Permutations.Split sp = splits.get(lvl);
        updateWord(word, lvl, sp, coord);

        if(coord.children.size() > 0) {

            System.out.println("coordsize: > 0 :" + coord);

            for(Permutations.SegmentIndexPath childCoord : coord.children) {
                runSplitAttackBuild(exec, handler, word, lvl+1, splits, childCoord, shaAlgo);
            }
        } else {
                runSplitAttackExec(exec, handler, word, lvl, sp, shaAlgo);
        }
    }

    private static void runSplitAttackExec(ExecutorService exec,
                                           ObjIntConsumer<byte[]> handler,
                                           byte[] word, final int lvl, Permutations.Split sp, String shaAlgo) {
        System.out.println("Work: " + Arrays.toString(word));
        for(int i = 0; i < sp.getColumnCount(); i++) {

            final byte[] columnWord = Arrays.copyOf(word, word.length);
            columnWord[columnWord.length-1] = sp.getKEndConstant(i);

            exec.submit(() -> {

                Permutations.addAndCarry(columnWord, sp.keyLen-1, lvl, GoogleTOTP.ENCODE_TABLE, handler);

            });
        }

    }

    private static void updateWord(byte[] word, int lvl, Permutations.Split sp, Permutations.SegmentIndexPath coord) {
        word[lvl] = sp.getSegmentConstant(coord.index);
    }


    /**
     * Run a single threaded attack simulation
     *
     * @param keyLen
     * @param alphabet
     * @param shaAlgo
     * @throws InterruptedException
     */
    public static void runAttack(int keyLen, byte[] alphabet, String shaAlgo) throws InterruptedException {

        long totalPermutations = (long) Math.pow(alphabet.length, keyLen);

        long start = System.currentTimeMillis();


        OTPToken[] stolenTokens = OTPToken.stealOTP(keyLen, alphabet, 10, shaAlgo);

        OTPToken firstToken = stolenTokens[0];

        System.out.println("Selected random key: " + Arrays.toString(firstToken.getKey()) + " ( " + asCharStr(firstToken.getKey()) + ") ==> " + firstToken.getOtp());


        int otp = firstToken.getOtp();

        AtomicLong counter = new AtomicLong();
        AtomicLong matchCounter = new AtomicLong();

        List<byte[]> matchedKeys = new ArrayList<>();

        ObjIntConsumer<byte[]> handler = (byte[] bts, int count) -> {


            if (count % 1000000 == 0 && count != 0) {
                counter.lazySet(count);
                System.err.println("Processed: " + count + " of " + totalPermutations + " " + (System.currentTimeMillis() - start) + "ms");
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

        System.out.println("Searched " + counter.get() + " " + ((int) (((double) counter.get() / totalPermutations) * 100)) + "% permutations in " + (end - start) + "ms found " + matchCounter.get());

        System.out.println("Printing match correlations: ");

        printOtpValues(stolenTokens, firstToken.getKey(), shaAlgo);

        System.out.println("--------------------------[Brute Force check]-------------------------------");

        for (byte[] matchedKey : matchedKeys) {
            printOtpValues(stolenTokens, matchedKey, shaAlgo);
        }


        System.out.println("--------------------------------------------------------------------");

    }


}
