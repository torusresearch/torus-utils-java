package org.torusresearch.torusutils.types;

public class FinalPubKeyData {

    public String walletAddress;
    public String x;
    public String y;

    public FinalPubKeyData(String walletAddress, String x, String y) {
        this.walletAddress = walletAddress;
        this.x = x;
        this.y = y;
    }

    public String getWalletAddress() {
        return walletAddress;
    }

    public String getX() {
        return x;
    }

    public String getY() {
        return y;
    }
}
