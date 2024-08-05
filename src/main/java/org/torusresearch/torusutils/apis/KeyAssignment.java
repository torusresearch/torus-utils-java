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
    private String share; // TODO: Check, this is base64, which decodes to hex bytes, this is the ciphertext
    private Ecies metadata; // TODO: This is omitCipherText, all the fields are hex bytes, not base64
    private GetOrSetNonceResult nonceResult;
    private Ecies share_metadata; // TODO: This is omitCipherText, all the fields are hex bytes, not base64
    private GetOrSetNonceResult nonce_data;

    //Old schema keys
    private PubKey PublicKey;
    private Integer Threshold;
    private HashMap<String, String[]> Verifiers;
    private String Share;
    private Ecies Metadata; // TODO: This is omitCipherText

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
        // Refactor this to return a single value, remove the other from the class.
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

