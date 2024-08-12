package org.torusresearch.torusutils.apis.responses;

import org.jetbrains.annotations.NotNull;

public class PubNonce {
    public final String x;
    public final String y;

    public PubNonce(@NotNull String x, @NotNull String y) {
        this.x = x;
        this.y = y;
    }
}