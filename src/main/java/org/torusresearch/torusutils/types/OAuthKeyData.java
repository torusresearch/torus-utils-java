package org.torusresearch.torusutils.types;

public class OAuthKeyData {

    private final String walletAddress;
    private final String X;
    private final String Y;
    private final String privKey;

    public OAuthKeyData(String walletAddress, String X, String Y, String privKey) {
        this.walletAddress = walletAddress;
        this.X = X;
        this.Y = Y;
        this.privKey = privKey;
    }

    public String getWalletAddress() {
        return walletAddress;
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
