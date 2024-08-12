package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class CommitmentRequestParams {
    public final String messageprefix;
    public final String tokencommitment;
    public final String temppubx;
    public final String temppuby;
    public final String timestamp;
    public final String verifieridentifier;

    public CommitmentRequestParams(@NotNull String messageprefix, @NotNull String tokencommitment, @NotNull String temppubx, @NotNull String temppuby, @Nullable String timestamp, @NotNull String verifieridentifier) {
        this.messageprefix = messageprefix;
        this.tokencommitment = tokencommitment;
        this.temppubx = temppubx;
        this.temppuby = temppuby;
        this.timestamp = timestamp;
        this.verifieridentifier = verifieridentifier;
    }
}
