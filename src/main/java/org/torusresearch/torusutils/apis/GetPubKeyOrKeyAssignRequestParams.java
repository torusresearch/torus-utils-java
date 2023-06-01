package org.torusresearch.torusutils.apis;

public class GetPubKeyOrKeyAssignRequestParams {
    private final String verifier;
    private final String verifier_id;
    private final String extendedVerifierId;
    private final boolean one_key_flow;

    private final boolean fetch_node_index;

    public GetPubKeyOrKeyAssignRequestParams(String _verifier, String _verifier_id, String _extendedVerifierId, boolean _one_key_flow,
                                             boolean _fetch_node_index) {
        verifier = _verifier;
        verifier_id = _verifier_id;
        this.extendedVerifierId = _extendedVerifierId;
        this.one_key_flow = _one_key_flow;
        this.fetch_node_index = _fetch_node_index;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getVerifier_id() {
        return verifier_id;
    }

    public String getExtendedVerifierId() {
        return extendedVerifierId;
    }

    public boolean isOne_key_flow() {
        return one_key_flow;
    }

    public boolean isFetch_node_index() {
        return fetch_node_index;
    }
}
