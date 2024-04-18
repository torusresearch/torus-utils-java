package org.torusresearch.torusutils.types;

public class TorusKey {

    public FinalKeyData finalKeyData;
    public OAuthKeyData oAuthKeyData;
    public SessionData sessionData;
    public Metadata metadata;
    public NodesData nodesData;

    public TorusKey(FinalKeyData finalKeyData, OAuthKeyData oAuthKeyData, SessionData sessionData, Metadata metadata, NodesData nodesData) {
        this.finalKeyData = finalKeyData;
        this.oAuthKeyData = oAuthKeyData;
        this.sessionData = sessionData;
        this.metadata = metadata;
        this.nodesData = nodesData;
    }

    public FinalKeyData getFinalKeyData() {
        return finalKeyData;
    }

    public OAuthKeyData getoAuthKeyData() {
        return oAuthKeyData;
    }

    public SessionData getSessionData() {
        return sessionData;
    }

    public Metadata getMetadata() {
        return metadata;
    }

    public NodesData getNodesData() {
        return nodesData;
    }
}
