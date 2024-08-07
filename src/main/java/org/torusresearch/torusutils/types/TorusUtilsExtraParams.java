package org.torusresearch.torusutils.types;

import java.util.List;

public class TorusUtilsExtraParams {
    private Boolean enable_verifier_id_hash; // most
    private String app_s; // meta
    private String app_id; // meta
    private String domain; // farcaster
    private String nonce; // farcaster
    private String message; // farcaster
    private String signature; // farcaster, passkey, webauthn
    private String clientDataJson; // passkey, webauthn
    private String authenticatorData; // passkey, webauthn
    private String publicKey; // passkey, webauthn
    private String challenge; // passkey, webauthn
    private String rpOrigin; // passkey, webauthn
    private String rpId; // passkey, webauthn
    private String jwk_endpoint; // passkey, jwt
    private List<String> default_node_set; // passkey, jwt
    private String jwt_verifier_id_field; // passkey, jwt
    private Boolean jwt_verifier_id_case_sensitive; // passkey, jwt
    private String jwk_keys; // passkey, jwt
    private List<String> jwt_validation_fields; // passkey, jwt
    private List<String> jwt_validation_values; // passkey, jwt
    private Integer index; // demo
    private String email; // demo
    private String id; // test, jwt, passkey
    private String correct_id_token; // test
    private String verify_param; // OrAggregate
    private Integer session_token_exp_second;
    private Integer threshold; // SingleID
    private String pub_k_x; // Signature
    private String pub_k_y; // Signature

    // Default constructor
    public TorusUtilsExtraParams() {
    }

    // Constructor with parameters
    public TorusUtilsExtraParams(
            Boolean enable_verifier_id_hash, String app_s, String app_id, String domain, String nonce, String message,
            String signature, String clientDataJson, String authenticatorData, String publicKey, String challenge,
            String rpOrigin, String rpId, String jwk_endpoint, List<String> default_node_set,
            String jwt_verifier_id_field, Boolean jwt_verifier_id_case_sensitive, String jwk_keys,
            List<String> jwt_validation_fields, List<String> jwt_validation_values, Integer index, String email,
            String id, String correct_id_token, String verify_param, Integer session_token_exp_second,
            Integer threshold, String pub_k_x, String pub_k_y) {

        this.enable_verifier_id_hash = enable_verifier_id_hash;
        this.app_s = app_s;
        this.app_id = app_id;
        this.domain = domain;
        this.nonce = nonce;
        this.message = message;
        this.signature = signature;
        this.clientDataJson = clientDataJson;
        this.authenticatorData = authenticatorData;
        this.publicKey = publicKey;
        this.challenge = challenge;
        this.rpOrigin = rpOrigin;
        this.rpId = rpId;
        this.jwk_endpoint = jwk_endpoint;
        this.default_node_set = default_node_set;
        this.jwt_verifier_id_field = jwt_verifier_id_field;
        this.jwt_verifier_id_case_sensitive = jwt_verifier_id_case_sensitive;
        this.jwk_keys = jwk_keys;
        this.jwt_validation_fields = jwt_validation_fields;
        this.jwt_validation_values = jwt_validation_values;
        this.index = index;
        this.email = email;
        this.id = id;
        this.correct_id_token = correct_id_token;
        this.verify_param = verify_param;
        this.session_token_exp_second = session_token_exp_second;
        this.threshold = threshold;
        this.pub_k_x = pub_k_x;
        this.pub_k_y = pub_k_y;
    }

    public Integer getSessionTokenExpSecond() {
        return session_token_exp_second;
    }

    public void setSessionTokenExpSecond(Integer session_token_exp_second) {
        this.session_token_exp_second = session_token_exp_second;
    }
}

