package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;

public class ShareRequestParams {
    @SuppressWarnings("unused")
    public final String encrypted = "yes";
    @SuppressWarnings("unused")
    public final boolean one_key_flow = true;
    @SuppressWarnings("unused")
    public final boolean use_temp = true;
    @SuppressWarnings("unused")
    public final boolean distributed_metadata = true;
    public final String client_time;
    public final ShareRequestItem[] item;

    public ShareRequestParams(@NotNull ShareRequestItem[] item, @NotNull String client_time) {
        this.item = item;
        this.client_time = client_time;
    }
}
