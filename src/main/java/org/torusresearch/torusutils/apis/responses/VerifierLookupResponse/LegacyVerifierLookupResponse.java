package org.torusresearch.torusutils.apis.responses.VerifierLookupResponse;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class LegacyVerifierLookupResponse {
    public final LegacyVerifierKey[] keys;
    @Nullable
    public final String server_time_offset;

    public  LegacyVerifierLookupResponse(@NotNull  LegacyVerifierKey[] keys, @Nullable String server_time_offset) {
        this.server_time_offset = server_time_offset;
        this.keys = keys;
    }
}
