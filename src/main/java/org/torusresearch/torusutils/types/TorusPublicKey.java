package org.torusresearch.torusutils.types;

public class TorusPublicKey {

    public OAuthPubKeyData oAuthPubKeyData;
    public FinalPubKeyData finalPubKeyData;
    public PubKeyMetadata metadata;
    public NodesData nodesData;
    private String address;

    public TorusPublicKey(String _address) {
        address = _address;
    }

    public TorusPublicKey(OAuthPubKeyData oAuthPubKeyData, FinalPubKeyData finalPubKeyData, PubKeyMetadata metadata, NodesData nodesData) {
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

    public PubKeyMetadata getMetadata() {
        return metadata;
    }

    public NodesData getNodesData() {
        return nodesData;
    }
}
