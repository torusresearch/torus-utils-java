package org.torusresearch.torusutils.types;

// TODO: This class is a bit of a mess for legacy reasons and should be cleaned up in future.

import org.jetbrains.annotations.Nullable;

public class TorusUtilsExtraParams {
    @Nullable
    public final  String nonce; // farcaster
    @Nullable
    public final String message; // farcaster
    @Nullable
    public final String signature; // farcaster, passkey, webauthn
    @Nullable
    public final String clientDataJson; // passkey, webauthn
    @Nullable
    public final String authenticatorData; // passkey, webauthn
    @Nullable
    public final String publicKey; // passkey, webauthn
    @Nullable
    public final String challenge; // passkey, webauthn
    @Nullable
    public final String rpOrigin; // passkey, webauthn
    @Nullable
    public final String rpId; // passkey, webauthn
    @Nullable
    public Integer session_token_exp_second;
    @Nullable
    public final Integer timestamp; // signature

    // Default constructor
    public TorusUtilsExtraParams() {
        this.nonce = null;
        this.message = null;
        this.signature = null;
        this.clientDataJson = null;
        this.authenticatorData = null;
        this.publicKey = null;
        this.challenge = null;
        this.rpOrigin = null;
        this.rpId = null;
        this.session_token_exp_second = null;
        this.timestamp = null;
    }

    @SuppressWarnings("unused")
    public TorusUtilsExtraParams(
            @Nullable Integer session_token_exp_second,
            @Nullable String nonce, @Nullable String message, @Nullable String signature, @Nullable String clientDataJson, @Nullable String authenticatorData,
            @Nullable String publicKey, @Nullable String challenge, @Nullable String rpOrigin, @Nullable String rpId, @Nullable Integer timestamp) {
        this.nonce = nonce;
        this.message = message;
        this.signature = signature;
        this.clientDataJson = clientDataJson;
        this.authenticatorData = authenticatorData;
        this.publicKey = publicKey;
        this.challenge = challenge;
        this.rpOrigin = rpOrigin;
        this.rpId = rpId;
        this.session_token_exp_second = session_token_exp_second;
        this.timestamp = timestamp;
    }
}

