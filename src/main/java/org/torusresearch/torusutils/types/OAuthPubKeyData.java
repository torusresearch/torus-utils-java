package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;


public class OAuthPubKeyData extends FinalPubKeyData {
    public OAuthPubKeyData(@NotNull String walletAddress, @NotNull String x, @NotNull String y) {
        super(walletAddress, x, y);
    }
}
