package org.torusresearch.torusutils.types;

import java.util.Objects;

public class OAuthPubKeyData {

    public String walletAddress;
    public String x;
    public String y;

    public OAuthPubKeyData(String walletAddress, String x, String y) {
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
