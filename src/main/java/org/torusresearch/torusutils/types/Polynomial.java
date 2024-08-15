package org.torusresearch.torusutils.types;

import static org.torusresearch.torusutils.helpers.KeyUtils.getOrderOfCurve;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class Polynomial {
    private final BigInteger[] polynomial;

    public Polynomial(@NotNull BigInteger[] polynomial) {
        this.polynomial = polynomial;
    }

    public int getThreshold() {
        return polynomial.length;
    }

    public BigInteger polyEval(@NotNull BigInteger x) {
        BigInteger xi = x;
        BigInteger sum = BigInteger.ZERO;
        sum = sum.add(polynomial[0]);

        for (int i = 1; i < polynomial.length; i++) {
            BigInteger tmp = xi.multiply(polynomial[i]);
            sum = sum.add(tmp).mod(getOrderOfCurve());
            xi = xi.multiply(x).mod(getOrderOfCurve());
        }

        return sum;
    }

    public Map<String, Share> generateShares(@NotNull BigInteger[] shareIndexes) {
        Map<String, Share> shares = new LinkedHashMap<>();
        for (int x = 0; x < shareIndexes.length; x++) {
            String hexString = String.format("%064x", shareIndexes[x]);
            shares.put(hexString, new Share(shareIndexes[x], polyEval(shareIndexes[x])));
        }
        return shares;
    }
}

