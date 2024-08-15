package org.torusresearch.torusutils.types.common;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;

public class TorusPublicKey {

    public OAuthPubKeyData oAuthKeyData;
    public FinalPubKeyData finalKeyData;
    public Metadata metadata;
    public NodesData nodesData;

    public TorusPublicKey(@NotNull OAuthPubKeyData oAuthKeyData, @NotNull FinalPubKeyData finalKeyData, @NotNull Metadata metadata, @NotNull NodesData nodesData) {
        this.oAuthKeyData = oAuthKeyData;
        this.finalKeyData = finalKeyData;
        this.metadata = metadata;
        this.nodesData = nodesData;
    }

    public OAuthPubKeyData getoAuthKeyData() {
        return oAuthKeyData;
    }

    public FinalPubKeyData getFinalKeyData() {
        return finalKeyData;
    }

    public Metadata getMetadata() {
        return metadata;
    }

    public NodesData getNodesData() {
        return nodesData;
    }
}
