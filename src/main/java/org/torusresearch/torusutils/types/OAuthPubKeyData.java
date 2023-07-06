package org.torusresearch.torusutils.types;

import java.util.Objects;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OAuthPubKeyData)) return false;
        OAuthPubKeyData that = (OAuthPubKeyData) o;
        return getEvmAddress().equals(that.getEvmAddress()) && getX().equals(that.getX()) && getY().equals(that.getY());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getEvmAddress(), getX(), getY());
    }
}
