package org.torusresearch.torusutils.helpers;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierLookupResponse;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Common {
    private Common() {
    }

    public static KeyResult normalizeKeyResult(@NotNull VerifierLookupResponse result) {
        Boolean isNewKey = false;
        if (result.is_new_key != null) {
            isNewKey = result.is_new_key;
        }
        KeyResult finalResult = new KeyResult(isNewKey);
        if (result.keys.length > 0) {
            VerifierKey finalKey = result.keys[0];
            finalResult.keys = new VerifierKey[]{ finalKey };
        }
        return finalResult;
    }

    public static String padLeft(@NotNull String inputString, @NotNull Character padChar, int length) {
        if (inputString.length() >= length) return inputString;
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append(padChar);
        }
        sb.append(inputString);
        return sb.toString();
    }

    public static List<List<Integer>> kCombinations(@NotNull List<Integer> set, int k) {
        List<List<Integer>> combs = new ArrayList<>();

        if ((k == 0) || k > set.size())
        {
            return combs;
        }

        if (k == set.size()) {
            combs.add(set);
            return combs;
        }

        if (k == 1) {
            for (Integer i : set) {
                ArrayList<Integer> arrList = new ArrayList<>();
                arrList.add(i);
                combs.add(arrList);
            }
            return combs;
        }

        for (int i = 0; i < ((set.size() - k) + 1); i++) {
            List<List<Integer>> tailCombs = kCombinations(set.subList(i + 1, set.size()), k - 1);
            for (List<Integer> tailComb : tailCombs) {
                List<Integer> prependedComb = new ArrayList<>();
                prependedComb.add(set.get(i));
                prependedComb.addAll(tailComb);
                combs.add(prependedComb);
            }
        }
        return combs;
    }

    public static Integer calculateMedian(@NotNull List<Integer> arr) {
        int arrSize = arr.size();

        if (arrSize == 0) return 0;

        Collections.sort(arr);

        // odd length
        if (arrSize % 2 != 0) {
            return arr.get(arrSize / 2);
        }

        // return average of two mid values in case of even arrSize
        Integer mid1 = arr.get(arrSize / 2 - 1);
        Integer mid2 = arr.get(arrSize / 2);
        return (mid1+mid2)/2;
    }

    public static String strip04Prefix(@NotNull String pubKey) {
        if (pubKey.startsWith("04")) {
            return pubKey.substring(2);
        }
        return pubKey;
    }

    public static boolean isEmpty(@org.jetbrains.annotations.Nullable final CharSequence cs) {
        return cs == null || cs.length() == 0;
    }
}
