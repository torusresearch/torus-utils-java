package org.torusresearch.torusutils.apis.responses.VerifierLookupResponse;

import org.jetbrains.annotations.NotNull;

public class LegacyVerifierKey {
    public final String pub_key_X;
    public final String pub_key_Y;
    public final String address;

    public LegacyVerifierKey(@NotNull String pub_key_X, @NotNull String pub_key_Y, @NotNull String address) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.address = address;

    }
}
