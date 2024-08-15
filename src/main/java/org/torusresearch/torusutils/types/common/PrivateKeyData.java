package org.torusresearch.torusutils.types.common;

import org.jetbrains.annotations.NotNull;

public class PrivateKeyData {
    private final String oAuthKey;
    private final String oAuthPubKey;
    private final String nonce;
    private final String signingKey;
    private final String signingPubKey;
    private final String finalKey;
    private final String finalPubKey;

    public PrivateKeyData(@NotNull String oAuthKey, @NotNull String oAuthPubKey, @NotNull String nonce, @NotNull String signingKey, @NotNull String signingPubKey, @NotNull String finalKey, @NotNull String finalPubKey) {
        this.oAuthKey = oAuthKey;
        this.oAuthPubKey = oAuthPubKey;
        this.nonce = nonce;
        this.signingKey = signingKey;
        this.signingPubKey = signingPubKey;
        this.finalKey = finalKey;
        this.finalPubKey = finalPubKey;
    }

    public String getOAuthKey() {
        return oAuthKey;
    }

    public String getOAuthPubKey() {
        return oAuthPubKey;
    }

    public String getNonce() {
        return nonce;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public String getSigningPubKey() {
        return signingPubKey;
    }

    @SuppressWarnings("unused")
    public String getFinalKey() {
        return finalKey;
    }

    public String getFinalPubKey() {
        return finalPubKey;
    }

    @Override
    public String toString() {
        return "PrivateKeyData{" +
                "oAuthKey='" + oAuthKey + '\'' +
                ", oAuthPubKey='" + oAuthPubKey + '\'' +
                ", nonce='" + nonce + '\'' +
                ", signingKey='" + signingKey + '\'' +
                ", signingPubKey='" + signingPubKey + '\'' +
                ", finalKey='" + finalKey + '\'' +
                ", finalPubKey='" + finalPubKey + '\'' +
                '}';
    }
}
