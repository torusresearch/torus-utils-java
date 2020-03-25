package org.torusresearch.torusutils.apis;

public class ShareRequestItem {
    private String idtoken;
    private NodeSignature[] nodesignatures;
    private String verifieridentifier;
    private String verifier_id;
    public ShareRequestItem(String _verifier_id, String _idtoken, NodeSignature[] _nodesignatures, String _verifieridentifier) {
        verifier_id = _verifier_id;
        idtoken = _idtoken;
        nodesignatures = _nodesignatures;
        verifieridentifier = _verifieridentifier;
    }

    public String getIdtoken() {
        return idtoken;
    }

    public NodeSignature[] getNodesignatures() {
        return nodesignatures;
    }

    public String getVerifieridentifier() {
        return verifieridentifier;
    }

    public String getVerifier_id() {
        return verifier_id;
    }
}
