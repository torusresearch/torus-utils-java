package org.torusresearch.torusutils.apis;

public class Ecies {

    private String iv;
    private String ephemPublicKey;
    private String mac;
    private String mode;
    private String ciphertext;

    public Ecies(String iv, String ephemPublicKey, String ciphertext, String mac, String mode) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.ciphertext = ciphertext;
        this.mode = mode;
    }

    public Ecies(String iv, String ephemPublicKey, String ciphertext, String mac) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.ciphertext = ciphertext;
        this.mode = "AES256";
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
