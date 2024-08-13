package org.torusresearch.torusutils.types.common;

import org.jetbrains.annotations.NotNull;

import java.util.Objects;

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

    public String getSignature() {
        return signature;
    }

    public String getNode_pubx() {
        return node_pubx;
    }

    public String getNode_puby() {
        return node_puby;
    }


    // TODO: Check this
    @Override
    public int hashCode() {
        return Objects.hash(signature);
    }

    // TODO: Check this
    @Override
    public boolean equals(Object obj) {
        SessionToken newObj = (SessionToken)obj;
        return this.signature != newObj.signature;
    }
}
