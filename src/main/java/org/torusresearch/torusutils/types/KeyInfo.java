package org.torusresearch.torusutils.types;

public class KeyInfo {
    private String pubKeyX;
    private String pubKeyY;
    private String address;
    private GetOrSetNonceResult nonceData;
    private Long createdAt;

    public KeyInfo(String pubKeyX, String pubKeyY, String address, GetOrSetNonceResult nonceData, Long createdAt) {
        this.pubKeyX = pubKeyX;
        this.pubKeyY = pubKeyY;
        this.address = address;
        this.nonceData = nonceData;
        this.createdAt = createdAt;
    }

    public String getPubKeyX() {
        return pubKeyX;
    }

    public String getPubKeyY() {
        return pubKeyY;
    }

    public String getAddress() {
        return address;
    }

    public GetOrSetNonceResult getNonceData() {
        return nonceData;
    }

    public Long getCreatedAt() {
        return createdAt;
    }
}
