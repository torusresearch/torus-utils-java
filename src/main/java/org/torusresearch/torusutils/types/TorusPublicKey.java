package org.torusresearch.torusutils.types;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TorusPublicKey)) return false;
        TorusPublicKey that = (TorusPublicKey) o;
        return getoAuthKeyData().equals(that.getoAuthKeyData()) && getFinalKeyData().equals(that.getFinalKeyData()) && getMetadata().equals(that.getMetadata()) && getNodesData().equals(that.getNodesData());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getoAuthKeyData(), getFinalKeyData(), getMetadata(), getNodesData());
    }
}
