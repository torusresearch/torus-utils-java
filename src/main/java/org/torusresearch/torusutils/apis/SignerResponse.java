package org.torusresearch.torusutils.apis;

import com.google.gson.annotations.SerializedName;

public class SignerResponse {
    @SerializedName("torus-timestamp")
    private final String torus_timestamp;
    @SerializedName("torus-nonce")
    private final String torus_nonce;
    @SerializedName("torus-signature")
    private final String torus_signature;

    public SignerResponse(String _torus_timestamp, String _torus_nonce, String _torus_signature) {
        torus_timestamp = _torus_timestamp;
        torus_nonce = _torus_nonce;
        torus_signature = _torus_signature;
    }

    public String getTorus_timestamp() {
        return torus_timestamp;
    }

    public String getTorus_nonce() {
        return torus_nonce;
    }

    public String getTorus_signature() {
        return torus_signature;
    }
}
