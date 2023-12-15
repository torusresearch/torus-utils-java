package org.torusresearch.torusutils.types;

public class OAuthKeyData {

    public String evmAddress;
    public String X;
    public String Y;
    public String privKey;

    public OAuthKeyData(String evmAddress, String X, String Y, String privKey) {
        this.evmAddress = evmAddress;
        this.X = X;
        this.Y = Y;
        this.privKey = privKey;
    }

    public String getEvmAddress() {
        return evmAddress;
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
