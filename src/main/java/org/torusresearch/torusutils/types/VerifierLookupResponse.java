package org.torusresearch.torusutils.types;

import java.math.BigInteger;
import java.util.List;

public class VerifierLookupResponse {
    private List<KeyInfo> keys;
    private boolean isNewKey;
    private BigInteger nodeIndex;
    private String server_time_offset;

    public VerifierLookupResponse(List<KeyInfo> keys, boolean isNewKey, BigInteger nodeIndex, String server_time_offset) {
        this.keys = keys;
        this.isNewKey = isNewKey;
        this.nodeIndex = nodeIndex;
        this.server_time_offset = server_time_offset;
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

    public String getServerTimeOffset() {
        return server_time_offset;
    }
}
