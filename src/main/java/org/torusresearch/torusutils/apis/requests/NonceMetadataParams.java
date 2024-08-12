package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.types.TorusKeyType;

public class NonceMetadataParams {
    @Nullable
    public String namespace;
    public String pub_key_X;
    public String pub_key_Y;
    @Nullable
    public SetNonceData set_data;
    @Nullable
    public TorusKeyType key_type;

    public String signature;
    public String encodedData;
    @Nullable
    public String seed;

    public NonceMetadataParams(@Nullable String namespace, @NotNull String pub_key_X, @NotNull String pub_key_Y, @NotNull SetNonceData set_data,
                               @NotNull TorusKeyType key_type, @NotNull String signature, @NotNull String encodedData, @Nullable String seed) {
        this.namespace = namespace;
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.signature = signature;
        this.encodedData = encodedData;
        this.seed = seed;
        this.set_data = set_data;
        this.key_type = key_type;
    }
}
