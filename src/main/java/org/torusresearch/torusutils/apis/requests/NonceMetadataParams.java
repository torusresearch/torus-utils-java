package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.types.TorusKeyType;

import java.util.Objects;

public class NonceMetadataParams {
    @Nullable
    public final String namespace;
    public final  String pub_key_X;
    public final  String pub_key_Y;
    public final  SetNonceData set_data;
    @Nullable
    public final TorusKeyType keyType;

    public final  String signature;
    public final  String encodedData;
    @Nullable
    public final  String seed;

    public NonceMetadataParams(@NotNull String pub_key_X, @NotNull String pub_key_Y, @NotNull SetNonceData set_data, @NotNull String encodedData, @NotNull String signature, @Nullable String namespace, @Nullable TorusKeyType keyType, @Nullable String seed) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.set_data = set_data;
        this.encodedData = encodedData;
        this.signature = signature;
        this.namespace = namespace;
        this.keyType = keyType;
        this.seed = seed;
    }

    // TODO: Check this
    @Override
    public int hashCode() {
        return Objects.hash(namespace, pub_key_X, pub_key_Y, set_data, keyType, signature, encodedData, seed);
    }
}

