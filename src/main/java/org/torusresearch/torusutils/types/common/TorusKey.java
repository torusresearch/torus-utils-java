package org.torusresearch.torusutils.types.common;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.Metadata;

public class TorusKey {

    private final FinalKeyData finalKeyData;
    private final OAuthKeyData oAuthKeyData;
    private final SessionData sessionData;

    private final Metadata metadata;
    private final NodesData nodesData;

    public TorusKey(@NotNull FinalKeyData finalKeyData, @NotNull OAuthKeyData oAuthKeyData, @NotNull SessionData sessionData, @NotNull Metadata metadata, @NotNull NodesData nodesData) {
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
