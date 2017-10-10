package org.funsec.util;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntFunction;
import java.util.function.ObjIntConsumer;

public class Permutations {

    public static void main(String arg[]) throws InterruptedException {
//        printAlphabetInfo(4, "ABC".getBytes());
        printAlphabetInfoSegment(3, "ABC".getBytes());

        for(Split split : splitKeySpace(4, "ABC".getBytes())){
            System.out.println(split);
        }

/*
         keyLen:  4
         Split{keyLen=4, alphabet=3, total=81, rows=27, segment_len=9, segments=3}
         Split{keyLen=2, alphabet=3, total=9, rows=3, segment_len=1, segments=3}

         */
    }

    public static final void printKeySpaceSplit(int keyLen, byte[] alphabet) {
        for(Split split : splitKeySpace(keyLen, alphabet)){
            System.out.println(split);
        }

    }

    /**
     * Print out all permutations for a key from an alphabet.<br/>
     * Total = alphabet_len^keyLen
     * Rows = total/alphabet_len
     * Column[i].k_end = alphabet[i]   => column 0, the last element in the tuple is a constant from alphabet[0] and so on.
     * <p>
     * Segments:
     */
    public static final void printAlphabetInfo(int keyLen, byte[] alphabet) {


        IntFunction<ObjIntConsumer<byte[]>> printer = (n) -> (bts, len) -> {
            int x = len % n;

            System.out.print("\t" + Utils.asCharStr(bts) + (x == 0 ? '\n' : ""));

        };


        int alphabetLen = alphabet.length;
        addAndCarry(keyLen, alphabet, printer.apply(alphabetLen));

        int total = (int) Math.pow(3, 4);
        int rows = (total / alphabetLen);
        int segment_len = rows / alphabetLen;
        int segments = rows / segment_len;

        System.out.println("total " + total + " rows: " + rows + " cols " + alphabetLen);

        for (int i = 0; i < alphabetLen; i++) {
            System.out.print("Column[" + i + "].K_end =>  " + ((char) alphabet[i]) + " ");
        }
        System.out.println();

        System.out.println("Segment_len: " + segment_len + " of " + segments + " segments");
    }

    public static final void printAlphabetInfoSegment(int keyLen, byte[] alphabet) {
        IntFunction<ObjIntConsumer<byte[]>> printer = (n) -> (bts, len) -> {
            int x = len % n;

            System.out.print("\t" + Utils.asCharStr(bts) + (x == 0 ? '\n' : ""));

        };


        Split split = new Split(keyLen, alphabet);

        addAndCarry(new byte[keyLen], 0, split, printer.apply(split.getColumnCount()));
    }


    /**
     *
     * Divide the keyspace into splits where each subsequent Split instance identifies a whole rectangle of keyspace with
     * the same amount of columns but 2 keys less.
     *
     * e.g
     * <pre>
     * AAAA	AAAB	AAAC
     * AABA	AABB	AABC
     * AACA	AACB	AACC
     *
     * ABAA	ABAB	ABAC
     * ABBA	ABBB	ABBC
     * ABCA	ABCB	ABCC
     *
     * ACAA	ACAB	ACAC
     * ACBA	ACBB	ACBC
     * ACCA	ACCB	ACCC
     *
     * BAAA	BAAB	BAAC
     * BABA	BABB	BABC
     * BACA	BACB	BACC
     * BBAA	BBAB	BBAC
     * BBBA	BBBB	BBBC
     * BBCA	BBCB	BBCC
     * BCAA	BCAB	BCAC
     * BCBA	BCBB	BCBC
     * BCCA	BCCB	BCCC
     * CAAA	CAAB	CAAC
     * CABA	CABB	CABC
     * CACA	CACB	CACC
     * CBAA	CBAB	CBAC
     * CBBA	CBBB	CBBC
     * CBCA	CBCB	CBCC
     * CCAA	CCAB	CCAC
     * CCBA	CCBB	CCBC
     * CCCA	CCCB	CCCC
     * </pre>
     *
     * splits[0] = {segments=3, segment_length=9, rows=27, word[col=0]=['A', ?, ?, 'A'],   word[col=1]=['A', ?, ?, 'B'],   word[col=2]=['A', ?, ?, 'C']}
     * splits[1] = {segments=3, segment_length=3, rows=9,  word[col=0]=['A', 'A', ?, 'A'], word[col=1]=['A', 'A', ?, 'B'], word[col=2]=['A', 'A', ?, 'C']}
     *
     * This means:
     *  each segment in split[1] is repeated splits[0].segments times and for each column where column.length == alphabet.length
     */
    public static final List<Split> splitKeySpace(int keyLen, byte[] alphabet, int splitLimit, int sizeLimit) {

        List<Split> splits = new ArrayList<>();
        Split split = new Split(keyLen, alphabet);

        splits.add(split);


        while (split.keyLen > 3 &&
                (split.total.longValue() > sizeLimit) &&
                splits.size() < splitLimit) {

            split = split.split();
            splits.add(split);
        }

        return splits;
    }

    public static final List<Split> splitKeySpace(int keyLen, byte[] alphabet) {
        return splitKeySpace(keyLen, alphabet, 4, 10);
    }

    /**
     * segmentIndexes are the segments from 0...segment_length in the last split that should be populated for each
     */
    public static void permutate(List<Split> split, int[] segmentIndexes) {

    }

    public static void addAndCarry(byte[] word, int wordI, Split segment, ObjIntConsumer<byte[]> handler) {
        addAndCarry(word, segment.keyLen, wordI, segment.alphabet, handler);
    }


    public static void addAndCarry(int len, byte[] alphabet, ObjIntConsumer<byte[]> handler) {
        addAndCarry(new byte[len], len, 0, alphabet, handler);
    }

    /**
     * Call the handler once for each permutation alphabet in len, calculated by count(alphabet)^len.
     */
    public static void addAndCarry(byte[] word, int len, int wordI, byte[] alphabet, ObjIntConsumer<byte[]> handler) {

        int[] index = new int[len];
        int q;

        int count = 0;

        while (true) {

            copy(len, alphabet, word, wordI, index);

            count++;

            try {
                handler.accept(word, count);
            } catch (RuntimeException rte) {
                return;
            }


            for (int i = len - 1; ; i--) {
                if (i < 0) return;

                q = index[i] + 1;
                index[i] = q;

                if (q == alphabet.length)
                    index[i] = 0;
                else
                    break;

            }
        }
    }


    private static final void copy(int len, byte[] alphabet, byte[] word, int wordI, int[] index) {
        for (int i = wordI; i < len; i++)
            word[i] = alphabet[index[i]];
    }

    /**
     * A Segment takes advantage of how permutations can be grouped into rows and columns.
     * Doing this give us insight into optimizing and splitting permutations into segments.
     * Segments can be split themselves into sub-segments.
     * <p>
     * total = alphabet_len ^ key_len
     * rows = total / alphabet_len
     * segment_len = rows / alphabet_len
     * segments = rows / segment_len
     * <p>
     * A segment represents N rows of columns data. The first item of a permutation tuple is constant within a segment,
     * and the last item is constant for each column ( the number of columns is equal to the alphabet size).
     * The permutations for each column can be calculated as if the key_len has been reduced by 2.
     * <p>
     * <p>
     * e.g
     * <pre>
     * AAAA	AAAB	AAAC
     * AABA	AABB	AABC
     * AACA	AACB	AACC
     * ABAA	ABAB	ABAC
     * ABBA	ABBB	ABBC
     * ABCA	ABCB	ABCC
     * ACAA	ACAB	ACAC
     * ACBA	ACBB	ACBC
     * ACCA	ACCB	ACCC
     * BAAA	BAAB	BAAC
     * BABA	BABB	BABC
     * BACA	BACB	BACC
     * BBAA	BBAB	BBAC
     * BBBA	BBBB	BBBC
     * BBCA	BBCB	BBCC
     * BCAA	BCAB	BCAC
     * BCBA	BCBB	BCBC
     * BCCA	BCCB	BCCC
     * CAAA	CAAB	CAAC
     * CABA	CABB	CABC
     * CACA	CACB	CACC
     * CBAA	CBAB	CBAC
     * CBBA	CBBB	CBBC
     * CBCA	CBCB	CBCC
     * CCAA	CCAB	CCAC
     * CCBA	CCBB	CCBC
     * CCCA	CCCB	CCCC
     * total 81 rows: 27 cols 3
     * Column[0].K_end =>  A Column[1].K_end =>  B Column[2].K_end =>  C
     * Segment_len: 9 of 3 segments
     * </pre>
     */
    public static class Split {

        public final int keyLen;
        public final byte[] alphabet;

        public final BigInteger total;
        public final BigInteger rows;
        public final BigInteger segment_len;
        public final int segments;

        public Split(int keyLen, byte[] alphabet) {

            this.keyLen = keyLen;
            this.alphabet = alphabet;

            BigInteger alphabetLen = new BigInteger(String.valueOf(alphabet.length));

            total = alphabetLen.pow(keyLen);
            rows = total.divide(alphabetLen);
            segment_len = rows.divide(alphabetLen);
            segments = rows.divide(segment_len).intValue(); //segment_len is never larger than the alphabet len
        }

        /**
         * The number of columns is always equal to the alphabet len
         *
         * @return
         */
        public int getColumnCount() {
            return alphabet.length;
        }

        /**
         * [x,x,x....K]
         *
         * @param col
         * @return byte for K which is constant throughout the column
         */
        public byte getKEndConstant(int col) {
            return alphabet[col];
        }

        public byte getSegmentConstant(int segmentIndex) {
            return alphabet[segmentIndex];
        }

        public Split split() {

            System.out.println("keyLen:  " + keyLen);
            if (keyLen < 3) {
                throw new RuntimeException("The segments cannot be split more " + keyLen);
            }

            return new Split(keyLen - 1, alphabet);
        }

        @Override
        public String toString() {
            return "Split{" +
                    "keyLen=" + keyLen +
                    ", alphabet=" + alphabet.length+
                    ", total=" + total +
                    ", rows=" + rows +
                    ", segment_len=" + segment_len +
                    ", segments=" + segments +
                    '}';
        }
    }

    public static final class SegmentIndexPath{

        public final int index;
        public final List<SegmentIndexPath> children;

        public SegmentIndexPath(int index, String str) {
            this(index, parsePath(str));
        }

        public SegmentIndexPath(int index) {
            this(index, new ArrayList<>());
        }

        public SegmentIndexPath(int index, List<SegmentIndexPath> children) {
            this.index = index;
            this.children = children;
        }


        public static List<SegmentIndexPath> parsePath(String str) {
            String[] paths = str.split(",");

            List<SegmentIndexPath> arr = new ArrayList<>();

            for(String path : paths) {

                String[] parts = path.split(":");

                if(parts.length == 1)
                    arr.add(new SegmentIndexPath(Integer.parseInt(parts[0])));
                else
                    arr.add(new SegmentIndexPath(Integer.parseInt(parts[0]), join(parts, ':', 1)));

            }

            return arr;
        }

        private static String join(String[] parts, char ch, int from) {
            StringBuilder buff = new StringBuilder();
            for(int i = from; i < parts.length; i++) {
                if(i != from)
                    buff.append(ch);

                buff.append(parts[i]);
            }

            return buff.toString();
        }

        @Override
        public String toString() {
            return "SegmentIndexPath{" +
                    "index=" + index +
                    ", children=" + children +
                    '}';
        }
    }

}
