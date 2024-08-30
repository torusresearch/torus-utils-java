package org.torusresearch.torusutils.apis.responses;

import org.jetbrains.annotations.NotNull;

public class CommitmentRequestResult {
    public final String signature;
    public final String data;
    public final String nodepubx;
    public final String nodepuby;
    public final String nodeindex;

    public CommitmentRequestResult(@NotNull String data, @NotNull String nodepubx, @NotNull String nodepuby, @NotNull String signature, @NotNull String nodeindex) {
        this.data = data;
        this.nodeindex = nodeindex;
        this.signature = signature;
        this.nodepubx = nodepubx;
        this.nodepuby = nodepuby;
    }
}
