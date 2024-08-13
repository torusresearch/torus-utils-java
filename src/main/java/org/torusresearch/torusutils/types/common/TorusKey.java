package org.torusresearch.torusutils.types.common;

import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.Metadata;

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
