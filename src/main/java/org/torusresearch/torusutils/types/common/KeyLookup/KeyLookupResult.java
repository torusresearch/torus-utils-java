package org.torusresearch.torusutils.types.common.KeyLookup;

import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.apis.JsonRPCRequest;
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
    public final JsonRPCRequest.JRPCResponse.ErrorInfo errorResult;

    public KeyLookupResult(@Nullable KeyResult keyResult, List<Integer> nodeIndexes, Integer server_time_offset, @Nullable GetOrSetNonceResult nonceResult, @Nullable JsonRPCRequest.JRPCResponse.ErrorInfo errorResult) {
        this.keyResult = keyResult;
        this.nodeIndexes = nodeIndexes;
        this.server_time_offset = server_time_offset;
        this.nonceResult = nonceResult;
        this.errorResult = errorResult;
    }
}
