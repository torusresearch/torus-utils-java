package org.torusresearch.torusutils.types.common.KeyLookup;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.apis.JsonRPCErrorInfo;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;

import java.util.List;

public class KeyLookupResult {
    @Nullable
    public final KeyResult keyResult;

    public final List<Integer> nodeIndexes;
    public final Integer server_time_offset;
    @Nullable
    public final GetOrSetNonceResult nonceResult;

    @Nullable
    public final JsonRPCErrorInfo errorResult;

    public KeyLookupResult(@Nullable KeyResult keyResult, @NotNull List<Integer> nodeIndexes, @NotNull Integer server_time_offset, @Nullable GetOrSetNonceResult nonceResult, @Nullable JsonRPCErrorInfo errorResult) {
        this.keyResult = keyResult;
        this.nodeIndexes = nodeIndexes;
        this.server_time_offset = server_time_offset;
        this.nonceResult = nonceResult;
        this.errorResult = errorResult;
    }
}
