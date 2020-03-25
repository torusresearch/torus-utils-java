package org.torusresearch.torusutils.apis;

public class ShareMetadata {
    private String iv;
    private String ephemPublicKey;
    private String mac;
    private String mode;

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
