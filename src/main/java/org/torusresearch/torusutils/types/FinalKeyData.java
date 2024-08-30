package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class FinalKeyData extends FinalPubKeyData {
    @Nullable
    private final String privKey;

    public FinalKeyData(@NotNull String walletAddress, @NotNull String X, @NotNull String Y, @Nullable String privKey) {
        super(walletAddress,X,Y);
        this.privKey = privKey;
    }

    @Nullable
    public String getPrivKey() {
        return privKey;
    }
}
