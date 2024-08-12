package org.torusresearch.torusutils.types;

// TODO: This class is a bit of a mess for legacy reasons and should be cleaned up in future.

public class TorusUtilsExtraParams {
    public final  String nonce; // farcaster
    public final String message; // farcaster
    public final String signature; // farcaster, passkey, webauthn
    public final String clientDataJson; // passkey, webauthn
    public final String authenticatorData; // passkey, webauthn
    public final String publicKey; // passkey, webauthn
    public final String challenge; // passkey, webauthn
    public final String rpOrigin; // passkey, webauthn
    public final String rpId; // passkey, webauthn
    public Integer session_token_exp_second;
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

    // Constructor with parameters
    public TorusUtilsExtraParams(
            Integer session_token_exp_second,
            String nonce, String message,
            String signature, String clientDataJson, String authenticatorData, String publicKey, String challenge,
            String rpOrigin, String rpId, Integer timestamp) {
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

