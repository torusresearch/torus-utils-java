package org.torusresearch.torusutils.types;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.Utils;

import java.math.BigInteger;

public class Point {
    private final BigInteger x;
    private final BigInteger y;
    @SuppressWarnings("unused")
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

    @SuppressWarnings("unused")
    public byte[] encode(String enc) throws Exception {
        String xPadded = Utils.padLeft(this.x.toString(16),'0', 64);
        String yPadded = Utils.padLeft(this.y.toString(16),'0', 64);
        switch (enc) {
            case "arr":
                return Hex.decode("04"+ xPadded + yPadded);
            case "elliptic-compressed":
                return KeyUtils.serializePublicKey(KeyUtils.deserializePublicKey(Hex.decode("04"+ xPadded + yPadded)), true);
            default:
                throw new IllegalArgumentException("Invalid encoding in Point");
        }
    }
}

