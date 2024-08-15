package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;

public class OAuthKeyData {

    private final String walletAddress;
    private final String X;
    private final String Y;
    private final String privKey;

    public OAuthKeyData(@NotNull String walletAddress, @NotNull String X, @NotNull String Y, @NotNull String privKey) {
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
