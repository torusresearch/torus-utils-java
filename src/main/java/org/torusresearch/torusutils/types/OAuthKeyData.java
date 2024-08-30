package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;

public class OAuthKeyData extends FinalKeyData {
    public OAuthKeyData(@NotNull String walletAddress, @NotNull String X, @NotNull String Y, @NotNull String privKey) {
        super(walletAddress, X, Y, privKey);
    }
}
