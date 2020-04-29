package org.torusresearch.torusutils.apis;

public class PubKey {
    private final String X;
    private final String Y;

    public PubKey(String _X, String _Y) {
        X = _X;
        Y = _Y;
    }

    public String getX() {
        return X;
    }

    public String getY() {
        return Y;
    }
}
