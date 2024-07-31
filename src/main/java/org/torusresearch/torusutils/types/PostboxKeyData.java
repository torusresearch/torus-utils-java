package org.torusresearch.torusutils.types;

public class PostboxKeyData {

    private String X;
    private String Y;
    private String privKey;

    public PostboxKeyData(String X, String Y, String privKey) {
        this.X = X;
        this.Y = Y;
        this.privKey = privKey;
    }

    public String getX() {
        return X;
    }

    public String getY() {
        return Y;
    }

    public String getPrivKey() {
        return privKey;
    }
}
