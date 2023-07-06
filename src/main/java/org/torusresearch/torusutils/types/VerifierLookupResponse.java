package org.torusresearch.torusutils.types;

import java.math.BigInteger;
import java.util.List;

public class VerifierLookupResponse {
    private List<KeyInfo> keys;
    private boolean isNewKey;
    private BigInteger nodeIndex;

    public VerifierLookupResponse(List<KeyInfo> keys, boolean isNewKey, BigInteger nodeIndex) {
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

    public BigInteger getNodeIndex() {
        return nodeIndex;
    }
}
