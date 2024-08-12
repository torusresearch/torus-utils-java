package org.torusresearch.torusutils.apis.responses.VerifierLookupResponse;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class VerifierLookupResponse {
    public final VerifierKey[] keys;
    @Nullable
    public final Boolean is_new_key;

    public final String node_index;
    @Nullable
    public final String server_time_offset;

    public  VerifierLookupResponse(@NotNull VerifierKey[] keys, @Nullable Boolean is_new_key, @NotNull String node_index, @Nullable String server_time_offset) {
        this.node_index = node_index;
        this.keys = keys;
        this.is_new_key = is_new_key;
        this.server_time_offset = server_time_offset;
    }
}
