package org.torusresearch.torusutils.apis.responses;

import org.jetbrains.annotations.NotNull;

public class GetMetadataResponse {
    public final String message;

    public GetMetadataResponse(@NotNull String message) {
        this.message = message;
    }
}
