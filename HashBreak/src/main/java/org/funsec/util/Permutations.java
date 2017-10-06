package org.funsec.util;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public class Permutations {

    /**
     * Call the handler once for each permutation alphabet in len, calculated by count(alphabet)^len.
     */
    public static void addAndCarry(int len, byte[] alphabet, Consumer<byte[]> handler) {
        byte[] word = new byte[len];
        int[] index = new int[len];

        while (true) {

            for (int i = 0; i < len; i++)
                word[i] = alphabet[index[i]];

            try {
                handler.accept(word);
            } catch (RuntimeException rte) {
                return;
            }


            for (int i = len - 1; ; i--) {
                if (i < 0) return;

                index[i]++;
                if (index[i] == alphabet.length)
                    index[i] = 0;
                else
                    break;

            }
        }
    }

}
