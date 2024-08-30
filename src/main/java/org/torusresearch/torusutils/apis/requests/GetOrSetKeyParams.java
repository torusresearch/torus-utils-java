package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class GetOrSetKeyParams {
    public final Boolean distributed_metadata;
    public final String verifier;
    public final String verifier_id;
    @Nullable
    public final String extended_verifier_id;
    public final Boolean one_key_flow;
    public final Boolean fetch_node_index;
    @Nullable
    public final String client_time;

    public GetOrSetKeyParams(@NotNull Boolean distributed_metadata, @NotNull String verifier, @NotNull String verifier_id, @Nullable String extended_verifier_id, @NotNull Boolean one_key_flow, @NotNull Boolean fetch_node_index, @Nullable String client_time) {
        this.distributed_metadata = distributed_metadata;
        this.verifier = verifier;
        this.verifier_id = verifier_id;
        this.extended_verifier_id = extended_verifier_id;
        this.one_key_flow = one_key_flow;
        this.fetch_node_index = fetch_node_index;
        this.client_time = client_time;
    }
}
