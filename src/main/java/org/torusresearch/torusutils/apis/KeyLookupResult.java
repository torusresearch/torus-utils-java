package org.torusresearch.torusutils.apis;

import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.JRPCResponse;

import java.math.BigInteger;
import java.util.List;

// TODO: Come back to this
public class KeyLookupResult {
    @Nullable
    public final KeyResult keyResult;

    public final List<Integer> nodeIndexes;
    public final Integer server_time_offset;
    @Nullable
    public final GetOrSetNonceResult nonceResult;

    @Nullable
    public final JRPCResponse.ErrorInfo errorResult;

    public KeyLookupResult(@Nullable KeyResult keyResult, List<Integer> nodeIndexes, Integer server_time_offset, @Nullable GetOrSetNonceResult nonceResult, @Nullable JRPCResponse.ErrorInfo errorResult) {
        this.keyResult = keyResult;
        this.nodeIndexes = nodeIndexes;
        this.server_time_offset = server_time_offset;
        this.nonceResult = nonceResult;
        this.errorResult = errorResult;
    }
}
