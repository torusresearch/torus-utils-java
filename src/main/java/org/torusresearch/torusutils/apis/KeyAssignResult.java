package org.torusresearch.torusutils.apis;

public class KeyAssignResult {
    private KeyAssignment[] keys;
    private String[] session_tokens;
    private ShareMetadata[] session_token_metadata;
    private String[] session_token_sigs;
    private ShareMetadata[] session_token_sig_metadata;
    private String node_pubx;
    private String node_puby;

    public KeyAssignment[] getKeys() {
        return keys;
    }

    public ShareMetadata[] getSessionTokenMetadata() {
        return session_token_metadata;
    }

    public ShareMetadata[] getSessionTokenSigMetadata() {
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
}
