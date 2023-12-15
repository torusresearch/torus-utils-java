package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class Point {
    private BigInteger x;
    private BigInteger y;

    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
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
                String hexX = x.toString(16);
                String hexY = y.toString(16);
                byte[] prefix = hexStringToByteArray("04");
                byte[] encodedX = hexStringToByteArray(hexX);
                byte[] encodedY = hexStringToByteArray(hexY);
                return concatByteArrays(prefix, encodedX, encodedY);
            case "elliptic-compressed":
                // Implement the logic for encoding as elliptic-compressed
                // Return the encoded point as a byte array
                // You'll need to use the EC library or implement the encoding algorithm yourself
                throw new UnsupportedOperationException("Encoding as elliptic-compressed is not implemented yet");
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

    private byte[] concatByteArrays(byte[]... byteArrays) {
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

