package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.Nullable;

public class FinalKeyData {

    public String evmAddress;
    public String X;
    public String Y;

    @Nullable
    public String privKey;

    public FinalKeyData(String evmAddress, String X, String Y, @Nullable String privKey) {
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

    @Nullable
    public String getPrivKey() {
        return privKey;
    }
}
