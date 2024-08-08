package org.torusresearch.torusutils.types;

import static org.torusresearch.torusutils.helpers.KeyUtils.getOrderOfCurve;

import java.math.BigInteger;
import java.util.HashMap;

public class Polynomial {
    private BigInteger[] polynomial;

    public Polynomial(BigInteger[] polynomial) {
        this.polynomial = polynomial;
    }

    public int getThreshold() {
        return polynomial.length;
    }

    public BigInteger polyEval(BigInteger x) {
        BigInteger tmpX = x;
        BigInteger xi = tmpX;
        BigInteger sum = BigInteger.ZERO;
        BigInteger orderOfCurve = getOrderOfCurve();

        sum.add(polynomial[0]);

        for (int i = 0; i < polynomial.length; i++) {
            BigInteger tmp = xi.multiply(polynomial[i]);
            sum = sum.add(tmp).mod(orderOfCurve);
            xi = xi.multiply(tmpX).mod(orderOfCurve);
        }

        return sum;
    }

    public HashMap<String, Share> generateShares(BigInteger[] shareIndexes) {
        HashMap<String, Share> shares = new HashMap<>();

        for (int i = 0; i < shareIndexes.length; i++) {
            BigInteger shareIndex = shareIndexes[i];
            String hexString = String.format("%064x", shareIndex);
            shares.put(hexString, new Share(shareIndex, polyEval(shareIndex)));
        }

        return shares;
    }
}

