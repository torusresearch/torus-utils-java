package org.torusresearch.torusutils.types.common;

import org.jetbrains.annotations.NotNull;

public class SessionToken {

    private final String token;
    private final String signature;
    private final String node_pubx;
    private final String node_puby;

    public SessionToken(@NotNull String token, @NotNull String signature, @NotNull String node_pubx, @NotNull String node_puby) {
        this.token = token;
        this.signature = signature;
        this.node_pubx = node_pubx;
        this.node_puby = node_puby;
    }

    public String getToken() {
        return token;
    }

    @SuppressWarnings("unused")
    public String getSignature() {
        return signature;
    }

    @SuppressWarnings("unused")
    public String getNode_pubx() {
        return node_pubx;
    }

    @SuppressWarnings("unused")
    public String getNode_puby() {
        return node_puby;
    }
}
