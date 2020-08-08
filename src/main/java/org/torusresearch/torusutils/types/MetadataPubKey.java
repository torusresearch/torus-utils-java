package org.torusresearch.torusutils.types;

public class MetadataPubKey {
    private final String pub_key_X;
    private final String pub_key_Y;

    public MetadataPubKey(String pub_key_X, String pub_key_Y) {
        this.pub_key_X = pub_key_X;
        this.pub_key_Y = pub_key_Y;
    }

    public String getPub_key_X() {
        return pub_key_X;
    }

    public String getPub_key_Y() {
        return pub_key_Y;
    }
}
