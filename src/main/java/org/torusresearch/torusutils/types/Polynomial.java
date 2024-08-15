package org.torusresearch.torusutils.types;

import static org.torusresearch.torusutils.helpers.KeyUtils.getOrderOfCurve;

import java.math.BigInteger;
import java.util.HashMap;

public class Polynomial {
    private final BigInteger[] polynomial;

    public Polynomial(BigInteger[] polynomial) {
        this.polynomial = polynomial;
    }

    public int getThreshold() {
        return polynomial.length;
    }

    public BigInteger polyEval(BigInteger x) {
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

    public HashMap<String, Share> generateShares(BigInteger[] shareIndexes) {
        HashMap<String, Share> shares = new HashMap<>();

        for (BigInteger shareIndex : shareIndexes) {
            String hexString = String.format("%064x", shareIndex);
            shares.put(hexString, new Share(shareIndex, polyEval(shareIndex)));
        }

        return shares;
    }
}

