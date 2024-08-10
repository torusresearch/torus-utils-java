package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.apis.ecies.EciesHexOmitCipherText;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;

import java.util.HashMap;

public class KeyAssignment {
    //new schema keys
    private PubKey public_key;
    private String threshold;
    private String node_index;
    private HashMap<String, String[]> verifiers;
    private String share; // TODO: Check, this is base64, which decodes to hex bytes, this is the ciphertext
    private EciesHexOmitCipherText metadata; // TODO: This is omitCipherText, all the fields are hex bytes, not base64
    private GetOrSetNonceResult nonceResult;
    private EciesHexOmitCipherText share_metadata; // TODO: This is omitCipherText, all the fields are hex bytes, not base64
    private GetOrSetNonceResult nonce_data;

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

    public EciesHexOmitCipherText getShareMetadata() {
        return share_metadata;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }

    public String getNodeIndex() {
        return node_index;
    }

    public EciesHexOmitCipherText getMetadata() {
        return metadata;
    }

    public GetOrSetNonceResult getNonceData() {
        return nonce_data;
    }
}

