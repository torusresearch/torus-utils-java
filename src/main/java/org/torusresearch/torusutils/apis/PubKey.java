package org.torusresearch.torusutils.apis;

public class PubKey {
    private final String X;
    private final String Y;
    private final String SignerX;
    private final String SignerY;

    public PubKey(String X, String Y, String SignerX, String SignerY) {
        this.X = X;
        this.Y = Y;
        this.SignerX = SignerX;
        this.SignerY = SignerY;
    }

    public String getX() {
        return X;
    }

    public String getY() {
        return Y;
    }

    public String getSignerX() {
        return SignerX;
    }

    public String getSignerY() {
        return SignerY;
    }
}
