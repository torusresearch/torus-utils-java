package org.torusresearch.torusutils.apis;

public class KeyAssignResult {
    private KeyAssignment[] keys;
    private String[] session_tokens;
    private Ecies[] session_token_metadata;
    private String[] session_token_sigs;
    private Ecies[] session_token_sig_metadata;
    private String node_pubx;
    private String node_puby;
    private String is_new_key;

    private String server_time_offset;

    public KeyAssignment[] getKeys() {
        return keys;
    }

    public Ecies[] getSessionTokenMetadata() {
        return session_token_metadata;
    }

    public Ecies[] getSessionTokenSigMetadata() {
        return session_token_sig_metadata;
    }

    public String[] getSessionTokens() {
        return session_tokens;
    }

    public String[] getSessionTokenSigs() {
        return session_token_sigs;
    }

    public String getNodePubx() {
        return node_pubx;
    }

    public String getNodePuby() {
        return node_puby;
    }

    public String getIsNewKey() {
        return is_new_key;
    }

    public String getServerTimeOffset() {
        return server_time_offset;
    }
}
