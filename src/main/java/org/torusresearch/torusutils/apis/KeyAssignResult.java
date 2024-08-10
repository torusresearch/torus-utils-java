package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.apis.ecies.EciesHexOmitCipherText;

public class KeyAssignResult {
    private KeyAssignment[] keys;
    private String[] session_tokens;
    private EciesHexOmitCipherText[] session_token_metadata; // This is omitciphertexthex
    private String[] session_token_sigs; // this is the ciphertext
    private EciesHexOmitCipherText[] session_token_sig_metadata; // This is omitciphertexthex
    private String node_pubx;
    private String node_puby;
    private String is_new_key;

    private String server_time_offset;

    public KeyAssignment[] getKeys() {
        return keys;
    }

    public EciesHexOmitCipherText[] getSessionTokenMetadata() {
        return session_token_metadata;
    }

    public EciesHexOmitCipherText[] getSessionTokenSigMetadata() {
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

    public void setServerTimeOffset(String server_time_offset) {
        this.server_time_offset = server_time_offset;
    }
}
