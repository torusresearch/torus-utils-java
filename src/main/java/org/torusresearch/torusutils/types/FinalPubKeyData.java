package org.torusresearch.torusutils.types;

import java.util.Objects;

public class FinalPubKeyData {

    public String evmAddress;
    public String x;
    public String y;

    public FinalPubKeyData(String evmAddress, String x, String y) {
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
        if (!(o instanceof FinalPubKeyData)) return false;
        FinalPubKeyData that = (FinalPubKeyData) o;
        return getEvmAddress().equals(that.getEvmAddress()) && getX().equals(that.getX()) && getY().equals(that.getY());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getEvmAddress(), getX(), getY());
    }
}
