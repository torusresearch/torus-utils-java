package org.torusresearch.torusutils.apis;

public class ShareMetadata {

    private String iv;
    private String ephemPublicKey;
    private String mac;
    private String mode;
    private String ciphertext;

    public ShareMetadata(String iv, String ephemPublicKey, String ciphertext, String mac) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.ciphertext = ciphertext;
    }

    public String getIv() {
        return iv;
    }

    public String getEphemPublicKey() {
        return ephemPublicKey;
    }

    public String getMac() {
        return mac;
    }

    public String getMode() {
        return mode;
    }

    public String getCiphertext() {
        return ciphertext;
    }
}
