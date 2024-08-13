package org.torusresearch.torusutils.types.common.ecies;

public class EciesHexOmitCipherText {
    private final String iv;
    private final String ephemPublicKey;
    private final String mac;
    private final String mode;

    public EciesHexOmitCipherText(String iv, String ephemPublicKey, String mac, String mode) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.mode = mode;
    }

    public EciesHexOmitCipherText(String iv, String ephemPublicKey, String mac) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
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
}
