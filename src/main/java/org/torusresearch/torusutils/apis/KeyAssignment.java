package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.types.GetOrSetNonceResult;

import java.util.HashMap;

public class KeyAssignment {
    private String Index;
    private PubKey PublicKey;
    private Integer Threshold;
    private HashMap<String, String[]> Verifiers;
    private String Share;
    private ShareMetadata Metadata;
    private GetOrSetNonceResult nonceResult;

    public KeyAssignment() {
    }

    public String getIndex() {
        return Index;
    }

    public PubKey getPublicKey() {
        return PublicKey;
    }

    public Integer getThreshold() {
        return Threshold;
    }

    public HashMap<String, String[]> getVerifiers() {
        return Verifiers;
    }

    public String getShare() {
        return Share;
    }

    public ShareMetadata getMetadata() {
        return Metadata;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }
}
