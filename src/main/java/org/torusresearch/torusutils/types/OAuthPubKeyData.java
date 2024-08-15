package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;

import java.util.Objects;

public class OAuthPubKeyData {

    private final String walletAddress;
    private final String x;
    private final String y;

    public OAuthPubKeyData(@NotNull String walletAddress, @NotNull String x, @NotNull String y) {
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
