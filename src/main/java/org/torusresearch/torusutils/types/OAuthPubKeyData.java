package org.torusresearch.torusutils.types;

public class OAuthPubKeyData {

    public String evmAddress;
    public String x;
    public String y;

    public OAuthPubKeyData(String evmAddress, String x, String y) {
        this.evmAddress = evmAddress;
        this.x = x;
        this.y = y;
    }

    public String getEvmAddress() {
        return evmAddress;
    }

    public String getX() {
        return x;
    }

    public String getY() {
        return y;
    }
}
