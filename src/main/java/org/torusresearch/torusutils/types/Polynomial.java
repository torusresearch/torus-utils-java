package org.torusresearch.torusutils.types;

import static org.torusresearch.torusutils.TorusUtils.secp256k1N;

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

    public BigInteger polyEval(String x) {
        BigInteger tmpX = new BigInteger(x, 16);
        BigInteger xi = new BigInteger(tmpX.toByteArray());
        BigInteger sum = BigInteger.ZERO.add(polynomial[0]);
        for (int i = 1; i < polynomial.length; i++) {
            BigInteger tmp = xi.multiply(polynomial[i]);
            sum = sum.add(tmp);
            sum = sum.mod(secp256k1N);
            xi = xi.multiply(new BigInteger(tmpX.toByteArray()));
            xi = xi.mod(secp256k1N);
        }
        return sum;
    }

    public HashMap<BigInteger, Share> generateShares(BigInteger[] shareIndexes) {
        BigInteger[] newShareIndexes = new BigInteger[shareIndexes.length];
        for (int i = 0; i < shareIndexes.length; i++) {
            BigInteger index = shareIndexes[i];
            newShareIndexes[i] = index;
        }

        HashMap<BigInteger, Share> shares = new HashMap<>();
        for (BigInteger shareIndex : newShareIndexes) {
            shares.put(shareIndex, new Share(shareIndex, polyEval(shareIndex.toString(16))));
        }
        return shares;
    }
}

