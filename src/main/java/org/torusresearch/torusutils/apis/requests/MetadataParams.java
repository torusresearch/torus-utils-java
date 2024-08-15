package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.types.common.TorusKeyType;

public class MetadataParams {
    @Nullable
    public final String namespace;
    public final String pub_key_X;
    public final String pub_key_Y;
    @Nullable
    public final TorusKeyType key_type;
    public final SetData set_data;
    public final String signature;

    public MetadataParams(@NotNull String pub_key_X, @NotNull String pub_key_Y, @NotNull SetData set_data, @NotNull String signature, @Nullable String namespace, @Nullable TorusKeyType key_type) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.set_data = set_data;
        this.signature = signature;
        this.key_type = key_type;
        this.namespace = namespace;
    }
}
