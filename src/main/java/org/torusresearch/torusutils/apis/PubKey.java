package org.torusresearch.torusutils.apis;

import org.jetbrains.annotations.NotNull;

public class PubKey {
    private final String X;
    private final String Y;

    public PubKey(@NotNull String X, @NotNull String Y) {
        this.X = X;
        this.Y = Y;
    }

    public String getX() {
        return X;
    }

    public String getY() {
        return Y;
    }
}
