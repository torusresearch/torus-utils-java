package org.torusresearch.torusutils.types;

public class OAuthKeyData {

    public String walletAddress;
    public String X;
    public String Y;
    public String privKey;

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
