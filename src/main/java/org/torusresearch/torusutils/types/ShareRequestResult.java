package org.torusresearch.torusutils.types;

import java.util.List;

public class ShareRequestResult {
    private List<KeyAssignment> keys;
    private List<String> sessionTokens;
    private List<EciesHex> sessionTokenMetadata;
    private List<String> sessionTokenSigs;
    private List<EciesHex> sessionTokenSigMetadata;
    private String nodePubx;
    private String nodePuby;

    public List<KeyAssignment> getKeys() {
        return keys;
    }

    public void setKeys(List<KeyAssignment> keys) {
        this.keys = keys;
    }

    public List<String> getSessionTokens() {
        return sessionTokens;
    }

    public void setSessionTokens(List<String> sessionTokens) {
        this.sessionTokens = sessionTokens;
    }

    public List<EciesHex> getSessionTokenMetadata() {
        return sessionTokenMetadata;
    }

    public void setSessionTokenMetadata(List<EciesHex> sessionTokenMetadata) {
        this.sessionTokenMetadata = sessionTokenMetadata;
    }

    public List<String> getSessionTokenSigs() {
        return sessionTokenSigs;
    }

    public void setSessionTokenSigs(List<String> sessionTokenSigs) {
        this.sessionTokenSigs = sessionTokenSigs;
    }

    public List<EciesHex> getSessionTokenSigMetadata() {
        return sessionTokenSigMetadata;
    }

    public void setSessionTokenSigMetadata(List<EciesHex> sessionTokenSigMetadata) {
        this.sessionTokenSigMetadata = sessionTokenSigMetadata;
    }

    public String getNodePubx() {
        return nodePubx;
    }

    public void setNodePubx(String nodePubx) {
        this.nodePubx = nodePubx;
    }

    public String getNodePuby() {
        return nodePuby;
    }

    public void setNodePuby(String nodePuby) {
        this.nodePuby = nodePuby;
    }
}

