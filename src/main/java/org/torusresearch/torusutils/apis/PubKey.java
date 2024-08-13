package org.torusresearch.torusutils.apis;

public class PubKey {
    private final String X;
    private final String Y;

    public PubKey(String X, String Y) {
        this.X = X;
        this.Y = Y;
    }

    public String getX() {
        return X;
    }

    public String getY() {
        return Y;
    }
}
