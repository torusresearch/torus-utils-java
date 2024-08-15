package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.helpers.KeyUtils.getOrderOfCurve;

import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.Polynomial;
import org.torusresearch.torusutils.types.Share;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.reactivex.annotations.Nullable;

public class Lagrange {

    public static BigInteger generatePrivateExcludingIndexes(@NotNull List<BigInteger> shareIndexes) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        BigInteger key = new BigInteger(Common.padLeft(Hex.toHexString(KeyUtils.serializePrivateKey(KeyUtils.generateKeyPair().getPrivate())), '0', 64), 16);

        if (shareIndexes.contains(key)) {
            return generatePrivateExcludingIndexes(shareIndexes);
        }

        return key;
    }

    public static BigInteger[] generateEmptyBNArray(int length) {
        BigInteger[] array = new BigInteger[length];
        Arrays.fill(array, BigInteger.ZERO);
        return array;
    }

    public static BigInteger denominator(int i, @NotNull Point[] innerPoints) {
        BigInteger result = BigInteger.ONE;
        BigInteger xi = innerPoints[i].getX();
        for (int j = 0; j < innerPoints.length; j++) {
            if (i != j) {
                BigInteger tmp = xi;
                tmp = (tmp.subtract(innerPoints[j].getX()).mod(getOrderOfCurve()));
                result = result.multiply(tmp).mod(getOrderOfCurve());
            }
        }
        return result;
    }

    public static BigInteger[] interpolationPoly(int i, @NotNull Point[] innerPoints) {
        BigInteger[] coefficients = generateEmptyBNArray(innerPoints.length);
        BigInteger d = denominator(i, innerPoints);
        if (d.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Denominator for interpolationPoly is 0");
        }

        coefficients[0] = d.modInverse(getOrderOfCurve());

        for (int k = 0; k < innerPoints.length; k++) {
            BigInteger[] newCoefficients = generateEmptyBNArray(innerPoints.length);
            if (k != i) {
                int j = (k < i) ? k + 1 : k;
                j -= 1;

                while (j >= 0) {
                    newCoefficients[j + 1] = newCoefficients[j + 1].add(coefficients[j]).mod(getOrderOfCurve());
                    BigInteger tmp = innerPoints[k].getX();
                    tmp = tmp.multiply(coefficients[j]).mod(getOrderOfCurve());
                    newCoefficients[j] = newCoefficients[j].subtract(tmp).mod(getOrderOfCurve());
                    j -= 1;
                }
                coefficients = newCoefficients;
            }
        }

        return coefficients;
    }

    public static Point[] pointSort(@NotNull Point[] innerPoints) {
        Point[] pointsClone = Arrays.copyOf(innerPoints, innerPoints.length);
        Arrays.sort(pointsClone, Comparator.comparing(Point::getX));
        return pointsClone;
    }
    @SuppressWarnings("unused")
    private static List<Point> pointSort(@NotNull List<Point> innerPoints) {
        List<Point> pointArrClone = new ArrayList<>(innerPoints);
        pointArrClone.sort(Comparator.comparing(Point::getX));
        return pointArrClone;
    }

    public static Polynomial lagrange(@NotNull Point[] unsortedPoints) {
        Point[] sortedPoints = pointSort(unsortedPoints);
        BigInteger[] polynomial = generateEmptyBNArray(sortedPoints.length);
        for (int i = 0; i < sortedPoints.length; i++) {
            BigInteger[] coefficients = interpolationPoly(i, sortedPoints);
            for (int k = 0; k < sortedPoints.length; k++) {
                BigInteger tmp = sortedPoints[i].getY();
                tmp = tmp.multiply(coefficients[k]).mod(getOrderOfCurve());
                polynomial[k] = polynomial[k].add(tmp).mod(getOrderOfCurve());
            }
        }
        return new Polynomial(polynomial);
    }

    public static Polynomial lagrangeInterpolatePolynomial(@NotNull Point[] points) {
        return lagrange(points);
    }

    public static BigInteger lagrangeInterpolation(@NotNull BigInteger[] shares, @NotNull BigInteger[] nodeIndex) throws TorusUtilError {
        if (shares.length != nodeIndex.length) {
            return null;
        }

        int sharesDecrypt = 0;

        BigInteger secret = BigInteger.ZERO;
        for (int i = 0; i < shares.length; i++) {
            BigInteger upper = BigInteger.ONE;
            BigInteger lower = BigInteger.ONE;
            for (int j = 0; j < shares.length; j++) {
                if (i != j) {
                    upper = upper.multiply(nodeIndex[j].negate()).mod(getOrderOfCurve());
                    BigInteger temp = nodeIndex[i].subtract(nodeIndex[j]).mod(getOrderOfCurve());
                    lower = lower.multiply(temp).mod(getOrderOfCurve());
                }
            }
            BigInteger inverse = lower.modInverse(getOrderOfCurve());
            BigInteger delta = upper.multiply(inverse).mod(getOrderOfCurve());
            delta = delta.multiply(shares[i]).mod(getOrderOfCurve());
            secret = secret.add(delta).mod(getOrderOfCurve());
            sharesDecrypt += 1;
        }

        if (secret.equals(BigInteger.ZERO)) {
            throw TorusUtilError.INTERPOLATION_FAILED;
        }

        if (sharesDecrypt == shares.length) {
            return secret;
        }

        throw TorusUtilError.INTERPOLATION_FAILED;
    }

    public static Polynomial generateRandomPolynomial(int degree, @Nullable BigInteger secret, @Nullable List<Share> deterministicShares) throws Exception {
        BigInteger actualS = secret;
        if (actualS == null) {
            List<BigInteger> excludeList = new ArrayList<>();
            excludeList.add(actualS);
            actualS = generatePrivateExcludingIndexes(excludeList);
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
        Map<String, Point> points = new LinkedHashMap<>();

        // Add deterministic shares to points map
        for (Share share : deterministicShares) {
            points.put(Common.padLeft(share.getShareIndex().toString(16), '0', 64), new Point(share.getShareIndex(), share.getShare()));
        }

        // Calculate remaining shares to fill the polynomial
        int remainingDegree = degree - deterministicShares.size();
        for (int i = 0; i < remainingDegree; i++) {
            List<BigInteger> excludeList = new ArrayList<>();
            excludeList.add(BigInteger.ZERO);
            BigInteger shareIndex = generatePrivateExcludingIndexes(excludeList);

            // Ensure unique share index
            while (points.containsKey(Common.padLeft(shareIndex.toString(16),'0', 64))) {
                shareIndex = generatePrivateExcludingIndexes(excludeList);
            }

            String serializedKey = Common.padLeft(Hex.toHexString(KeyUtils.serializePrivateKey(KeyUtils.generateKeyPair().getPrivate())),'0',64);
            points.put(Common.padLeft(shareIndex.toString(16),'0',64),
                    new Point(shareIndex, new BigInteger(serializedKey, 16)));
        }

        // Add point for zero index
        points.put("0", new Point(BigInteger.ZERO, actualS));

        // Interpolate polynomial using Lagrange interpolation
        return lagrangeInterpolatePolynomial(new ArrayList<>(points.values()).toArray(new Point[0]));
    }
}
