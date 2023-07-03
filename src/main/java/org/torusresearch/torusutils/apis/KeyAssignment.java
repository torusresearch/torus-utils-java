package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.helpers.Utils;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;

import java.util.HashMap;

public class KeyAssignment {
    private Index index;
    private PubKey public_key;
    private Integer threshold;
    private Long node_index;
    private HashMap<String, String[]> verifiers;
    private String share;
    private ShareMetadata metadata;
    private GetOrSetNonceResult nonceResult;
    private ShareMetadata share_metadata;
    private GetOrSetNonceResult nonce_data;

    private PubKey PublicKey;
    private Integer Threshold;
    private HashMap<String, String[]> Verifiers;
    private String Share;
    private ShareMetadata Metadata;

    public KeyAssignment() {
    }

    public Index getIndex() {
        return index;
    }

    public PubKey getPublicKey(String network) {
        if (Utils.isSapphireNetwork(network)) {
            return public_key;
        } else {
            return PublicKey;
        }
    }

    public Integer getThreshold() {
        return threshold;
    }

    public HashMap<String, String[]> getVerifiers() {
        return verifiers;
    }

    public String getShare(String network) {
        if (Utils.isSapphireNetwork(network)) {
            return share;
        } else {
            return Share;
        }
    }

    public ShareMetadata getShareMetadata() {
        return share_metadata;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }

    public Long getNodeIndex() {
        return node_index;
    }

    public ShareMetadata getMetadata(String network) {
        if (Utils.isSapphireNetwork(network)) {
            return metadata;
        } else {
            return Metadata;
        }
    }

    public GetOrSetNonceResult getNonceData() {
        return nonce_data;
    }


    public PubKey getPublicKey() {
        return PublicKey;
    }

    public Integer getLegacyThreshold() {
        return Threshold;
    }


    public String getLegacyShare() {
        return Share;
    }

    public ShareMetadata getLegacyMetadata() {
        return Metadata;
    }
}

