package org.torusresearch.torusutils.types;

import java.util.List;

public class VerifierLookupResponse {
    private List<KeyInfo> keys;
    private boolean isNewKey;
    private int nodeIndex;

    public VerifierLookupResponse(List<KeyInfo> keys, boolean isNewKey, int nodeIndex) {
        this.keys = keys;
        this.isNewKey = isNewKey;
        this.nodeIndex = nodeIndex;
    }

    public List<KeyInfo> getKeys() {
        return keys;
    }

    public boolean isNewKey() {
        return isNewKey;
    }

    public int getNodeIndex() {
        return nodeIndex;
    }
}
