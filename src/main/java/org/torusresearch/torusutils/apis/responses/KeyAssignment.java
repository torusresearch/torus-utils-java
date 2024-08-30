package org.torusresearch.torusutils.apis.responses;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.apis.PubKey;
import org.torusresearch.torusutils.types.common.ecies.EciesHexOmitCipherText;

public class KeyAssignment {
    public final String index;
    public final PubKey public_key;
    public final Integer threshold;
    public final Integer node_index;
    public final String share; // Note: This is in base64, must be decoded before decrypting
    public final EciesHexOmitCipherText share_metadata;
    @Nullable
    public final GetOrSetNonceResult nonce_data;

    public KeyAssignment(@NotNull String index, @NotNull PubKey public_key, @NotNull Integer threshold, @NotNull Integer node_index, @NotNull String share, @NotNull EciesHexOmitCipherText share_metadata, @Nullable GetOrSetNonceResult nonce_data) {
        this.index = index;
        this.public_key = public_key;
        this.threshold = threshold;
        this.node_index = node_index;
        this.share = share;
        this.share_metadata = share_metadata;
        this.nonce_data = nonce_data;
    }
}

