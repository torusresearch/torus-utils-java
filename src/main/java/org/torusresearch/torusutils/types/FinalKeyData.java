package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.Nullable;

public class FinalKeyData {

    public String walletAddress;
    public String X;
    public String Y;

    @Nullable
    public String privKey;

    public FinalKeyData(String walletAddress, String X, String Y, @Nullable String privKey) {
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
