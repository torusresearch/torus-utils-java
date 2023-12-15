package org.torusresearch.torusutils.types;

public class NonceMetadataParams {

    private String namespace;
    private String pub_key_X;
    private String pub_key_Y;
    private SetNonceData set_data;
    private String signature;

    public NonceMetadataParams(String pub_key_X, String pub_key_Y, SetNonceData setNonceData, String signatureBase64) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
        this.set_data = setNonceData;
        this.signature = signatureBase64;
    }

    public String getNamespace() {
        return namespace;
    }

    public String getPub_key_X() {
        return pub_key_X;
    }

    public String getPub_key_Y() {
        return pub_key_Y;
    }

    public SetNonceData getSet_data() {
        return set_data;
    }

    public String getSignature() {
        return signature;
    }
}
