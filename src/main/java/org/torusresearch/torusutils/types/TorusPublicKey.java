package org.torusresearch.torusutils.types;

import java.util.Objects;

public class TorusPublicKey {

    public OAuthPubKeyData oAuthPubKeyData;
    public FinalPubKeyData finalPubKeyData;
    public Metadata metadata;
    public NodesData nodesData;

    public TorusPublicKey(OAuthPubKeyData oAuthPubKeyData, FinalPubKeyData finalPubKeyData, Metadata metadata, NodesData nodesData) {
        this.oAuthPubKeyData = oAuthPubKeyData;
        this.finalPubKeyData = finalPubKeyData;
        this.metadata = metadata;
        this.nodesData = nodesData;
    }

    public OAuthPubKeyData getoAuthPubKeyData() {
        return oAuthPubKeyData;
    }

    public FinalPubKeyData getFinalPubKeyData() {
        return finalPubKeyData;
    }

    public Metadata getMetadata() {
        return metadata;
    }

    public NodesData getNodesData() {
        return nodesData;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TorusPublicKey)) return false;
        TorusPublicKey that = (TorusPublicKey) o;
        return getoAuthPubKeyData().equals(that.getoAuthPubKeyData()) && getFinalPubKeyData().equals(that.getFinalPubKeyData()) && getMetadata().equals(that.getMetadata()) && getNodesData().equals(that.getNodesData());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getoAuthPubKeyData(), getFinalPubKeyData(), getMetadata(), getNodesData());
    }
}
