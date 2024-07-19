package org.torusresearch.torusutils.types;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;

public class Point {
    private final BigInteger x;
    private final BigInteger y;
    private final ECDomainParameters ecCurve;

    public Point(String x, String y) {
        this.x = new BigInteger(x, 16);
        this.y = new BigInteger(y, 16);
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        this.ecCurve = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        this.ecCurve = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public byte[] encode(String enc) {
        switch (enc) {
            case "arr":
                return concatenateByteArrays(
                        hexStringToByteArray("04"),
                        hexStringToByteArray(this.x.toString(16)),
                        hexStringToByteArray(this.y.toString(16))
                );
            case "elliptic-compressed":
                return ecCurve.getCurve().createPoint(x, y).getEncoded(true);
            default:
                throw new IllegalArgumentException("Invalid encoding in Point");
        }
    }

    private byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] byteArray = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return byteArray;
    }

    private byte[] concatenateByteArrays(byte[]... byteArrays) {
        int totalLength = 0;
        for (byte[] byteArray : byteArrays) {
            totalLength += byteArray.length;
        }
        byte[] result = new byte[totalLength];
        int destPos = 0;
        for (byte[] byteArray : byteArrays) {
            System.arraycopy(byteArray, 0, result, destPos, byteArray.length);
            destPos += byteArray.length;
        }
        return result;
    }
}

