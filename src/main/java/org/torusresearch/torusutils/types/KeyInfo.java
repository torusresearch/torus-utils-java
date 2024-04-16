package org.torusresearch.torusutils.types;

public class KeyInfo {
    private String pub_key_X;
    private String pub_key_Y;
    private String address;

    private String signing_pub_key_X;

    private String signing_pub_key_Y;
    private GetOrSetNonceResult nonce_data;
    private Long createdAt;

    public KeyInfo(String pub_key_X, String pub_key_Y, String address, GetOrSetNonceResult nonce_data, Long createdAt, String signing_pub_key_X, String signing_pub_key_Y) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.address = address;
        this.nonce_data = nonce_data;
        this.createdAt = createdAt;
        this.signing_pub_key_X = signing_pub_key_X;
        this.signing_pub_key_Y = signing_pub_key_Y;
    }

    public String getPubKeyX() {
        return pub_key_X;
    }

    public String getPubKeyY() {
        return pub_key_Y;
    }

    public String getSigningPubKeyX() {
        return signing_pub_key_X;
    }

    public String getSigningPubKeyY() {
        return signing_pub_key_Y;
    }

    public String getAddress() {
        return address;
    }

    public GetOrSetNonceResult getNonceData() {
        return nonce_data;
    }

    public Long getCreatedAt() {
        return createdAt;
    }
}
