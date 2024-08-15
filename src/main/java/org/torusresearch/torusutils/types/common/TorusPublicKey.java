package org.torusresearch.torusutils.types.common;

import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.Metadata;

import java.util.Objects;

public class TorusPublicKey {

    public OAuthPubKeyData oAuthKeyData;
    public FinalPubKeyData finalKeyData;
    public Metadata metadata;
    public NodesData nodesData;

    public TorusPublicKey(OAuthPubKeyData oAuthKeyData, FinalPubKeyData finalKeyData, Metadata metadata, NodesData nodesData) {
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
