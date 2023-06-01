package org.torusresearch.torusutils.types;

public class ImportedShare {
    private final String pub_key_x;
    private final String pub_key_y;
    private final String encrypted_share;
    //encrypted_share_metadata
    private final Integer node_index;
    private final String key_type;
    private final String nonce_data;
    private final String nonce_signature;


    public ImportedShare(String pub_key_x, String pub_key_y, String encrypted_share, Integer node_index, String key_type, String nonce_data, String nonce_signature) {
        this.pub_key_x = pub_key_x;
        this.pub_key_y = pub_key_y;
        this.encrypted_share = encrypted_share;
        this.node_index = node_index;
        this.key_type = key_type;
        this.nonce_data = nonce_data;
        this.nonce_signature = nonce_signature;
    }

    public String getPub_key_x() {
        return pub_key_x;
    }

    public String getPub_key_y() {
        return pub_key_y;
    }

    public String getEncrypted_share() {
        return encrypted_share;
    }

    public Integer getNode_index() {
        return node_index;
    }

    public String getKey_type() {
        return key_type;
    }

    public String getNonce_data() {
        return nonce_data;
    }

    public String getNonce_signature() {
        return nonce_signature;
    }
}
