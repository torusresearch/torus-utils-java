package org.torusresearch.torusutilstest.helpers;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.helpers.Lagrange;
import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.Polynomial;

import java.math.BigInteger;
import java.util.ArrayList;

public class TestLagrangeInterpolation {
    @Test
    public void testLagrangeInterpolation() {
        ArrayList<Point> points = new ArrayList<>();
        points.add(new Point(BigInteger.ONE, new BigInteger(String.valueOf(2))));
        points.add(new Point(new BigInteger(String.valueOf(2)), new BigInteger(String.valueOf(5))));
        points.add(new Point(new BigInteger(String.valueOf(3)), new BigInteger(String.valueOf(10))));
        Polynomial poly = Lagrange.lagrangeInterpolatePolynomial(points.toArray(new Point[0]));

        ArrayList<BigInteger> xValues = new ArrayList<>();
        xValues.add(BigInteger.ONE);
        xValues.add(new BigInteger(String.valueOf(2)));
        xValues.add(new BigInteger(String.valueOf(3)));

        ArrayList<BigInteger> expectedYValues = new ArrayList<>();
        expectedYValues.add(new BigInteger(String.valueOf(2)));
        expectedYValues.add(new BigInteger(String.valueOf(5)));
        expectedYValues.add(new BigInteger(String.valueOf(10)));

        for (int i = 0; i < xValues.size(); i++) {
            BigInteger x = xValues.get(i);
            BigInteger expectedY = expectedYValues.get(i);

            BigInteger y = poly.polyEval(x);
            assertEquals(expectedY, y);
        }
    }
}
