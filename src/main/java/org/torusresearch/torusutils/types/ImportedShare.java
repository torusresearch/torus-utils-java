package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.apis.ecies.EciesHexOmitCipherText;

public class ImportedShare {

    private String oauth_pub_key_x;
    private String oauth_pub_key_y;
    private Point final_user_point;
    private String signing_pub_key_x;
    private String signing_pub_key_y;
    private String encryptedShare;
    private EciesHexOmitCipherText encryptedShareMetadata;
    private String encryptedSeed;
    private int node_index;
    private KeyType key_type;
    private String nonce_data;
    private String nonce_signature;

    public ImportedShare(String oauth_pub_key_x, String oauth_pub_key_y, Point final_user_point, String signing_pub_key_x, String signing_pub_key_y, String encryptedShare,
                         EciesHexOmitCipherText encryptedShareMetadata, String encryptedSeed, int node_index, KeyType key_type,
                         String nonce_data, String nonce_signature) {
        this.oauth_pub_key_x = oauth_pub_key_x;
        this.oauth_pub_key_y = oauth_pub_key_y;
        this.final_user_point = final_user_point;
        this.signing_pub_key_x = signing_pub_key_x;
        this.signing_pub_key_y = signing_pub_key_y;
        this.encryptedShare = encryptedShare;
        this.encryptedShareMetadata = encryptedShareMetadata;
        this.encryptedSeed = encryptedSeed;
        this.node_index = node_index;
        this.key_type = key_type;
        this.nonce_data = nonce_data;
        this.nonce_signature = nonce_signature;
    }

    public ImportedShare(String oauth_pub_key_x, String oauth_pub_key_y, Point final_user_point, String signing_pub_key_x, String signing_pub_key_y, String encryptedShare,
                         EciesHexOmitCipherText encryptedShareMetadata, int node_index, KeyType key_type,
                         String nonce_data, String nonce_signature) {
        this.oauth_pub_key_x = oauth_pub_key_x;
        this.oauth_pub_key_y = oauth_pub_key_y;
        this.final_user_point = final_user_point;
        this.signing_pub_key_x = signing_pub_key_x;
        this.signing_pub_key_y = signing_pub_key_y;
        this.encryptedShare = encryptedShare;
        this.encryptedShareMetadata = encryptedShareMetadata;
        this.node_index = node_index;
        this.key_type = key_type;
        this.nonce_data = nonce_data;
        this.nonce_signature = nonce_signature;
    }

    // Getters and Setters
    public String getOauth_pub_key_x() {
        return oauth_pub_key_x;
    }

    public void setOauth_pub_key_x(String oauth_pub_key_x) {
        this.oauth_pub_key_x = oauth_pub_key_x;
    }

    public String getOauth_pub_key_y() {
        return oauth_pub_key_y;
    }

    public void setOauth_pub_key_y(String oauth_pub_key_y) {
        this.oauth_pub_key_y = oauth_pub_key_y;
    }

    public Point getFinal_user_point() {
        return final_user_point;
    }

    public void setFinal_user_point(Point final_user_point) {
        this.final_user_point = final_user_point;
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

    public String getEncryptedShare() {
        return encryptedShare;
    }

    public void setEncryptedShare(String encryptedShare) {
        this.encryptedShare = encryptedShare;
    }

    public EciesHexOmitCipherText getEncryptedShareMetadata() {
        return encryptedShareMetadata;
    }

    public void setEncryptedShareMetadata(EciesHexOmitCipherText encryptedShareMetadata) {
        this.encryptedShareMetadata = encryptedShareMetadata;
    }

    public String getEncryptedSeed() {
        return encryptedSeed;
    }

    public void setEncryptedSeed(String encryptedSeed) {
        this.encryptedSeed = encryptedSeed;
    }

    public int getNode_index() {
        return node_index;
    }

    public void setNode_index(int node_index) {
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
}
