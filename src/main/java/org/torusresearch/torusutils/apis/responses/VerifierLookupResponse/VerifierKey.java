package org.torusresearch.torusutils.apis.responses.VerifierLookupResponse;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;

public class VerifierKey {
    public final String pub_key_X;
    public final String pub_key_Y;
    public final String address;
    @Nullable
    public final GetOrSetNonceResult nonce_data;
    @Nullable
    public final Integer created_at;
    // why is Integer better than primitive int?

    public VerifierKey(@NotNull String pub_key_X, @NotNull String pub_key_Y, @NotNull String address, @Nullable GetOrSetNonceResult nonce_data, @Nullable Integer created_at) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.address = address;
        this.nonce_data = nonce_data;
        this.created_at = created_at;
    }
}
