package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.types.GetOrSetNonceResult;

import java.math.BigInteger;
import java.util.HashMap;

public class KeyAssignment {
    private Index index;
    private PubKey public_key;
    private Integer threshold;
    private Long node_index;
    private HashMap<String, String[]> Verifiers;
    private String share;
    private ShareMetadata metadata;
    private GetOrSetNonceResult nonceResult;
    private ShareMetadata share_metadata;
    private GetOrSetNonceResult nonce_data;

    public KeyAssignment() {
    }

    public Index getIndex() {
        return index;
    }

    public PubKey getPublicKey() {
        return public_key;
    }

    public Integer getThreshold() {
        return threshold;
    }

    public HashMap<String, String[]> getVerifiers() {
        return Verifiers;
    }

    public String getShare() {
        return share;
    }

    public ShareMetadata getMetadata() {
        return metadata;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }

    public Long getNodeIndex() {
        return node_index;
    }

    public ShareMetadata getShareMetadata() {
        return share_metadata;
    }

    public GetOrSetNonceResult getNonceData() {
        return nonce_data;
    }
}

