package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;

public class GetNonceParams {
    public final String pub_key_X;
    public final String pub_key_Y;
    public final GetNonceSetDataParams set_data;

    public GetNonceParams(@NotNull String pub_key_X, @NotNull String pub_key_Y, @NotNull GetNonceSetDataParams set_data) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.set_data = set_data;
    }
}
