package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class FinalKeyData {

    private final String walletAddress;
    private final String X;
    private final String Y;

    @Nullable
    private final String privKey;

    public FinalKeyData(@NotNull String walletAddress, @NotNull String X, @NotNull String Y, @Nullable String privKey) {
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

    @Nullable
    public String getPrivKey() {
        return privKey;
    }
}
