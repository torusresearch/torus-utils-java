package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.apis.ecies.Ecies;

public class EncryptedSeed {
    private String encText;
    private String publicKey;
    private Ecies metadata;

    // Constructors
    public EncryptedSeed(String encText, String publicKey, Ecies metadata) {
        this.encText = encText;
        this.publicKey = publicKey;
        this.metadata = metadata;
    }

    // Getters and Setters
    public String getEncText() {
        return encText;
    }

    public void setEncText(String encText) {
        this.encText = encText;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Ecies getMetadata() {
        return metadata;
    }

    public void setMetadata(Ecies metadata) {
        this.metadata = metadata;
    }
}
