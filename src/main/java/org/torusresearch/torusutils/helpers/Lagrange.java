package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.TorusUtils.secp256k1N;

import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.Polynomial;
import org.torusresearch.torusutils.types.Share;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class Lagrange {

    public static BigInteger generatePrivateExcludingIndexes(List<BigInteger> shareIndexes) throws Exception {
        BigInteger key;
        do {
            key = new BigInteger(256, new Random());
        } while (shareIndexes.contains(key));

        return key;
    }

    public static BigInteger[] generateEmptyBNArray(int length) {
        BigInteger[] array = new BigInteger[length];
        Arrays.fill(array, BigInteger.ZERO);
        return array;
    }

    public static BigInteger denominator(int i, Point[] innerPoints) {
        BigInteger result = BigInteger.ONE;
        BigInteger xi = innerPoints[i].getX();

        for (int j = innerPoints.length - 1; j >= 0; j--) {
            if (i != j) {
                BigInteger tmp = xi.subtract(innerPoints[j].getX()).mod(KeyUtils.getOrderOfCurve());
                result = result.multiply(tmp).mod(KeyUtils.getOrderOfCurve());
            }
        }

        return result;
    }

    public static BigInteger[] interpolationPoly(int i, Point[] innerPoints) {
        BigInteger[] coefficients = generateEmptyBNArray(innerPoints.length);
        BigInteger d = denominator(i, innerPoints);

        if (d.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Denominator for interpolationPoly is 0");
        }

        coefficients[0] = d.modInverse(KeyUtils.getOrderOfCurve());

        for (int k = 0; k < innerPoints.length; k++) {
            BigInteger[] newCoefficients = generateEmptyBNArray(innerPoints.length);

            if (k != i) {
                int j = (k < i) ? k + 1 : k;
                j -= 1;

                while (j >= 0) {
                    newCoefficients[j + 1] = newCoefficients[j + 1].add(coefficients[j]).mod(KeyUtils.getOrderOfCurve());

                    BigInteger tmp = innerPoints[k].getX();
                    tmp = tmp.multiply(coefficients[j]).mod(KeyUtils.getOrderOfCurve());

                    newCoefficients[j] = newCoefficients[j].subtract(tmp).mod(KeyUtils.getOrderOfCurve());
                    j--;
                }

                coefficients = newCoefficients;
            }
        }

        return coefficients;
    }

    public static Point[] pointSort(Point[] innerPoints) {
        Point[] pointArrClone = Arrays.copyOf(innerPoints, innerPoints.length);
        Arrays.sort(pointArrClone, (p1, p2) -> p1.getX().compareTo(p2.getX()));
        return pointArrClone;
    }

    public static Polynomial lagrange(Point[] unsortedPoints) {
        Point[] sortedPoints = pointSort(unsortedPoints);
        BigInteger[] polynomial = generateEmptyBNArray(sortedPoints.length);

        for (int i = 0; i < sortedPoints.length; i++) {
            BigInteger[] coefficients = interpolationPoly(i, sortedPoints);

            for (int k = 0; k < sortedPoints.length; k++) {
                BigInteger tmp = sortedPoints[i].getY();
                tmp = tmp.multiply(coefficients[k]).mod(KeyUtils.getOrderOfCurve());
                polynomial[k] = polynomial[k].add(tmp).mod(KeyUtils.getOrderOfCurve());
            }
        }

        return new Polynomial(polynomial);
    }

    public static Polynomial lagrangeInterpolatePolynomial(Point[] points) {
        return lagrange(points);
    }

    public static BigInteger lagrangeInterpolation(BigInteger[] shares, BigInteger[] nodeIndex) {
        if (shares.length != nodeIndex.length) {
            return null;
        }
        BigInteger secret = new BigInteger("0");
        for (int i = 0; i < shares.length; i++) {
            BigInteger upper = new BigInteger("1");
            BigInteger lower = new BigInteger("1");
            for (int j = 0; j < shares.length; j++) {
                if (i != j) {
                    upper = upper.multiply(nodeIndex[j].negate());
                    upper = upper.mod(secp256k1N);
                    BigInteger temp = nodeIndex[i].subtract(nodeIndex[j]);
                    temp = temp.mod(secp256k1N);
                    lower = lower.multiply(temp).mod(secp256k1N);
                }
            }
            BigInteger delta = upper.multiply(lower.modInverse(secp256k1N)).mod(secp256k1N);
            delta = delta.multiply(shares[i]).mod(secp256k1N);
            secret = secret.add(delta);
        }
        return secret.mod(secp256k1N);
    }

    public static Polynomial generateRandomPolynomial(int degree, BigInteger secret, List<Share> deterministicShares) throws Exception {
        BigInteger actualS = secret;

        // Generate a random secret if not provided
        if (actualS == null) {
            actualS = generatePrivateExcludingIndexes(new ArrayList<>());
        }

        // If no deterministic shares provided, generate random shares
        if (deterministicShares == null) {
            List<BigInteger> poly = new ArrayList<>();
            poly.add(actualS);

            for (int i = 0; i < degree; i++) {
                BigInteger share = generatePrivateExcludingIndexes(poly);
                poly.add(share);
            }

            return new Polynomial(poly.toArray(new BigInteger[0]));
        }

        // Validate deterministic shares count
        if (deterministicShares.size() > degree) {
            throw new Exception("Deterministic shares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness");
        }

        // Initialize points map
        Map<String, Point> points = new HashMap<>();

        // Add deterministic shares to points map
        for (Share share : deterministicShares) {
            points.put(Utils.addLeadingZerosForLength64(share.getShareIndex().toString(16)), new Point(share.getShareIndex(), share.getShare()));
        }

        // Calculate remaining shares to fill the polynomial
        int remainingDegree = degree - deterministicShares.size();
        for (int i = 0; i < remainingDegree; i++) {
            BigInteger shareIndex = generatePrivateExcludingIndexes(new ArrayList<>());

            // Ensure unique share index
            while (points.containsKey(Utils.addLeadingZerosForLength64(shareIndex.toString(16)))) {
                shareIndex = generatePrivateExcludingIndexes(new ArrayList<>());
            }

            byte[] serializedKey = KeyUtils.serializePrivateKey(KeyUtils.generateKeyPair().getPrivate());
            String serializedHex = Utils.serializeHex(serializedKey);
            points.put(Utils.addLeadingZerosForLength64(shareIndex.toString(16)),
                    new Point(shareIndex, new BigInteger(serializedHex, 16)));
        }

        // Add point for zero index
        points.put("0", new Point(BigInteger.ZERO, actualS));

        // Interpolate polynomial using Lagrange interpolation
        return lagrangeInterpolatePolynomial(new ArrayList<>(points.values()).toArray(new Point[0]));
    }
}
