package org.torusresearch.torusutils.types;

import java.util.Objects;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FinalPubKeyData)) return false;
        FinalPubKeyData that = (FinalPubKeyData) o;
        return getWalletAddress().equals(that.getWalletAddress()) && getX().equals(that.getX()) && getY().equals(that.getY());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getWalletAddress(), getX(), getY());
    }
}
