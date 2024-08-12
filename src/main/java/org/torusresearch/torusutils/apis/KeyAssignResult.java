package org.torusresearch.torusutils.apis;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierLookupResponse;
import org.torusresearch.torusutils.types.JRPCResponse;

public class KeyAssignResult {
    public final KeyResult keyResult;
    public final VerifierLookupResponse[] lookupResponses;
    public final JRPCResponse.ErrorInfo errorMessage;

    public KeyAssignResult(@NotNull KeyResult keyResult, @NotNull VerifierLookupResponse[] lookupResponses, @NotNull JRPCResponse.ErrorInfo errorMessage) {
        this.keyResult = keyResult;
        this.lookupResponses = lookupResponses;
        this.errorMessage = errorMessage;
    }
}
