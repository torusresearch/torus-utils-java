package org.torusresearch.torusutils.types.common.meta;

import org.jetbrains.annotations.NotNull;

public class GetMetadataParams {
    public final String pub_key_X;
    public final String pub_key_Y;

    public GetMetadataParams(@NotNull String pub_key_X, @NotNull String pub_key_Y) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
    }
}
