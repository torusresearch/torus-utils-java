package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.Nullable;

public class SetNonceData {
    @Nullable
    public final String data;
    @Nullable
    public final String operation;

    public String seed = "";
    @Nullable
    public final String timestamp;

    public SetNonceData(@Nullable String operation, @Nullable String data, @Nullable String seed, @Nullable String timestamp) {
        this.data = data;
        this.operation = operation;
        if (seed != null) {
            this.seed = seed;
        }
        this.timestamp = timestamp;
    }
}
