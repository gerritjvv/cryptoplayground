package org.funsec;

import org.funsec.util.Permutations;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class PermutationsTest {

    @Test
    public void testSegmentsPath() {

        List<Permutations.SegmentIndexPath> paths = Permutations.SegmentIndexPath.parsePath("0:0:0,0:0:1,0:0:2");

        System.out.println(paths);
        assertEquals(3, paths.size());

    }

}
