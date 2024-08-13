package org.torusresearch.torusutils.apis.responses;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.apis.ecies.EciesHexOmitCipherText;

public class ShareRequestResult {
    public final KeyAssignment[] keys;
    public final String[] session_tokens;
    public final EciesHexOmitCipherText[] session_token_metadata;
    public final String[] session_token_sigs;
    public final EciesHexOmitCipherText[] session_token_sigs_metadata;
    public final String node_pubx;
    public final String node_puby;
    public final Boolean is_new_key;
    public String server_time_offset; // this is not final, it is modified by code

    public ShareRequestResult(@NotNull KeyAssignment[] keys, @NotNull String[] session_tokens, @NotNull EciesHexOmitCipherText[] session_token_metadata,
                              @NotNull String[] session_token_sigs, @NotNull EciesHexOmitCipherText[] session_token_sigs_metadata, @NotNull String node_pubx,
                              @NotNull String node_puby, @NotNull Boolean is_new_key, @Nullable String server_time_offset) {
        this.keys = keys;
        this.session_tokens = session_tokens;
        this.session_token_metadata = session_token_metadata;
        this.session_token_sigs = session_token_sigs;
        this.session_token_sigs_metadata = session_token_sigs_metadata;
        this.node_pubx = node_pubx;
        this.node_puby = node_puby;
        this.is_new_key = is_new_key;
        if (server_time_offset == null) {
            this.server_time_offset = "0";
        } else{
            this.server_time_offset = server_time_offset;
        }
    }
}
