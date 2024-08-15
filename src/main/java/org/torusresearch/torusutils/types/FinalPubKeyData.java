package org.torusresearch.torusutils.types;

public class FinalPubKeyData {

    private final String walletAddress;
    private final String x;
    private final String y;

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
