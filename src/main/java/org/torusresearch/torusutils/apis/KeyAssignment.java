package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.helpers.Utils;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;

import java.util.HashMap;

public class KeyAssignment {
    //new schema keys
    private PubKey public_key;
    private String threshold;
    private String node_index;
    private HashMap<String, String[]> verifiers;
    private String share;
    private Ecies metadata;
    private GetOrSetNonceResult nonceResult;
    private Ecies share_metadata;
    private GetOrSetNonceResult nonce_data;

    //Old schema keys
    private PubKey PublicKey;
    private Integer Threshold;
    private HashMap<String, String[]> Verifiers;
    private String Share;
    private Ecies Metadata;

    public KeyAssignment() {
    }

    public PubKey getPublicKey() {
        return public_key;
    }

    public String getThreshold() {
        return threshold;
    }

    public HashMap<String, String[]> getVerifiers() {
        return verifiers;
    }

    public String getShare() {
        return share;
    }

    public Ecies getShareMetadata() {
        return share_metadata;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }

    public String getNodeIndex() {
        return node_index;
    }

    public Ecies getMetadata(String network) {
        if (Utils.isSapphireNetwork(network)) {
            return share_metadata;
        } else {
            return Metadata;
        }
    }

    public GetOrSetNonceResult getNonceData() {
        return nonce_data;
    }


    public Integer getLegacyThreshold() {
        return Threshold;
    }


    public String getLegacyShare() {
        return Share;
    }

    public Ecies getLegacyMetadata() {
        return Metadata;
    }
}

