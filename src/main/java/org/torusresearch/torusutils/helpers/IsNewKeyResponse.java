package org.torusresearch.torusutils.helpers;

public class IsNewKeyResponse {

    public boolean isNewKey;
    public String publicKeyX;

    public IsNewKeyResponse(boolean isNewKey, String publicKeyX) {
        this.isNewKey = isNewKey;
        this.publicKeyX = publicKeyX;
    }

    public boolean isNewKey() {
        return isNewKey;
    }

    public String getPublicKeyX() {
        return publicKeyX;
    }
}
