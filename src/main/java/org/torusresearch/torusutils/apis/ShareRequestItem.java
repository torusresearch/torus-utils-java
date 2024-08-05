package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.types.KeyType;

import java.util.List;

public class ShareRequestItem {
    private String verifieridentifier;
    private String verifier_id;
    private String extended_verifier_id;
    private String idtoken;
    private NodeSignature[] nodesignatures;
    private String pub_key_x;
    private String pub_key_y;
    private String signing_pub_key_x;
    private String signing_pub_key_y;
    private String encrypted_share;
    private EciesHexOmitCipherText encrypted_share_metadata;
    private Integer node_index;
    private KeyType key_type;
    private String nonce_data;
    private String nonce_signature;
    private String[] sub_verifier_ids;
    private Integer session_token_exp_second;
    private VerifyParams[] verify_params;
    private String sss_endpoint;

    private Boolean enable_verifier_id_hash;
    private String app_s;
    private String app_id;
    private String domain;
    private String nonce;
    private String message;
    private String signature;
    private String clientDataJson;
    private String authenticatorData;
    private String publicKey;
    private String challenge;
    private String rpOrigin;
    private String rpId;
    private String jwk_endpoint;
    private List<String> default_node_set;
    private String jwt_verifier_id_field;
    private Boolean jwt_verifier_id_case_sensitive;
    private String jwk_keys;
    private List<String> jwt_validation_fields;
    private List<String> jwt_validation_values;
    private Integer index;
    private String email;
    private String id;
    private String correct_id_token;
    private String verify_param;
    private Integer threshold;
    private String pub_k_x;
    private String pub_k_y;

    public String getVerifieridentifier() {
        return verifieridentifier;
    }

    public void setVerifieridentifier(String verifieridentifier) {
        this.verifieridentifier = verifieridentifier;
    }

    public String getVerifier_id() {
        return verifier_id;
    }

    public void setVerifier_id(String verifier_id) {
        this.verifier_id = verifier_id;
    }

    public String getExtended_verifier_id() {
        return extended_verifier_id;
    }

    public void setExtended_verifier_id(String extended_verifier_id) {
        this.extended_verifier_id = extended_verifier_id;
    }

    public String getIdtoken() {
        return idtoken;
    }

    public void setIdtoken(String idtoken) {
        this.idtoken = idtoken;
    }

    public NodeSignature[] getNodesignatures() {
        return nodesignatures;
    }

    public void setNodesignatures(NodeSignature[] nodesignatures) {
        this.nodesignatures = nodesignatures;
    }

    public String getPub_key_x() {
        return pub_key_x;
    }

    public void setPub_key_x(String pub_key_x) {
        this.pub_key_x = pub_key_x;
    }

    public String getPub_key_y() {
        return pub_key_y;
    }

    public void setPub_key_y(String pub_key_y) {
        this.pub_key_y = pub_key_y;
    }

    public String getSigning_pub_key_x() {
        return signing_pub_key_x;
    }

    public void setSigning_pub_key_x(String signing_pub_key_x) {
        this.signing_pub_key_x = signing_pub_key_x;
    }

    public String getSigning_pub_key_y() {
        return signing_pub_key_y;
    }

    public void setSigning_pub_key_y(String signing_pub_key_y) {
        this.signing_pub_key_y = signing_pub_key_y;
    }

    public String getEncrypted_share() {
        return encrypted_share;
    }

    public void setEncrypted_share(String encrypted_share) {
        this.encrypted_share = encrypted_share;
    }

    public EciesHexOmitCipherText getEncrypted_share_metadata() {
        return encrypted_share_metadata;
    }

    public void setEncrypted_share_metadata(EciesHexOmitCipherText encrypted_share_metadata) {
        this.encrypted_share_metadata = encrypted_share_metadata;
    }

    public Integer getNode_index() {
        return node_index;
    }

    public void setNode_index(Integer node_index) {
        this.node_index = node_index;
    }

    public KeyType getKey_type() {
        return key_type;
    }

    public void setKey_type(KeyType key_type) {
        this.key_type = key_type;
    }

    public String getNonce_data() {
        return nonce_data;
    }

    public void setNonce_data(String nonce_data) {
        this.nonce_data = nonce_data;
    }

    public String getNonce_signature() {
        return nonce_signature;
    }

    public void setNonce_signature(String nonce_signature) {
        this.nonce_signature = nonce_signature;
    }

    public String[] getSub_verifier_ids() {
        return sub_verifier_ids;
    }

    public void setSub_verifier_ids(String[] sub_verifier_ids) {
        this.sub_verifier_ids = sub_verifier_ids;
    }

    public Integer getSession_token_exp_second() {
        return session_token_exp_second;
    }

    public void setSession_token_exp_second(Integer session_token_exp_second) {
        this.session_token_exp_second = session_token_exp_second;
    }

    public VerifyParams[] getVerify_params() {
        return verify_params;
    }

    public void setVerify_params(VerifyParams[] verify_params) {
        this.verify_params = verify_params;
    }

    public String getSss_endpoint() {
        return sss_endpoint;
    }

    public void setSss_endpoint(String sss_endpoint) {
        this.sss_endpoint = sss_endpoint;
    }

    public Boolean getEnable_verifier_id_hash() {
        return enable_verifier_id_hash;
    }

    public void setEnable_verifier_id_hash(Boolean enable_verifier_id_hash) {
        this.enable_verifier_id_hash = enable_verifier_id_hash;
    }

    public String getApp_s() {
        return app_s;
    }

    public void setApp_s(String app_s) {
        this.app_s = app_s;
    }

    public String getApp_id() {
        return app_id;
    }

    public void setApp_id(String app_id) {
        this.app_id = app_id;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getClientDataJson() {
        return clientDataJson;
    }

    public void setClientDataJson(String clientDataJson) {
        this.clientDataJson = clientDataJson;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public void setAuthenticatorData(String authenticatorData) {
        this.authenticatorData = authenticatorData;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getRpOrigin() {
        return rpOrigin;
    }

    public void setRpOrigin(String rpOrigin) {
        this.rpOrigin = rpOrigin;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getJwk_endpoint() {
        return jwk_endpoint;
    }

    public void setJwk_endpoint(String jwk_endpoint) {
        this.jwk_endpoint = jwk_endpoint;
    }

    public List<String> getDefault_node_set() {
        return default_node_set;
    }

    public void setDefault_node_set(List<String> default_node_set) {
        this.default_node_set = default_node_set;
    }

    public String getJwt_verifier_id_field() {
        return jwt_verifier_id_field;
    }

    public void setJwt_verifier_id_field(String jwt_verifier_id_field) {
        this.jwt_verifier_id_field = jwt_verifier_id_field;
    }

    public Boolean getJwt_verifier_id_case_sensitive() {
        return jwt_verifier_id_case_sensitive;
    }

    public void setJwt_verifier_id_case_sensitive(Boolean jwt_verifier_id_case_sensitive) {
        this.jwt_verifier_id_case_sensitive = jwt_verifier_id_case_sensitive;
    }

    public String getJwk_keys() {
        return jwk_keys;
    }

    public void setJwk_keys(String jwk_keys) {
        this.jwk_keys = jwk_keys;
    }

    public List<String> getJwt_validation_fields() {
        return jwt_validation_fields;
    }

    public void setJwt_validation_fields(List<String> jwt_validation_fields) {
        this.jwt_validation_fields = jwt_validation_fields;
    }

    public List<String> getJwt_validation_values() {
        return jwt_validation_values;
    }

    public void setJwt_validation_values(List<String> jwt_validation_values) {
        this.jwt_validation_values = jwt_validation_values;
    }

    public Integer getIndex() {
        return index;
    }

    public void setIndex(Integer index) {
        this.index = index;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCorrect_id_token() {
        return correct_id_token;
    }

    public void setCorrect_id_token(String correct_id_token) {
        this.correct_id_token = correct_id_token;
    }

    public String getVerify_param() {
        return verify_param;
    }

    public void setVerify_param(String verify_param) {
        this.verify_param = verify_param;
    }

    public Integer getThreshold() {
        return threshold;
    }

    public void setThreshold(Integer threshold) {
        this.threshold = threshold;
    }

    public String getPub_k_x() {
        return pub_k_x;
    }

    public void setPub_k_x(String pub_k_x) {
        this.pub_k_x = pub_k_x;
    }

    public String getPub_k_y() {
        return pub_k_y;
    }

    public void setPub_k_y(String pub_k_y) {
        this.pub_k_y = pub_k_y;
    }
}
