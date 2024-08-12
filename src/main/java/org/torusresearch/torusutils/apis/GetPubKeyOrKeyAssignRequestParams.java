package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.types.TorusKeyType;

public class GetPubKeyOrKeyAssignRequestParams {
    private final String verifier;
    private final String verifier_id;
    private final String extended_verifier_id;
    private final boolean one_key_flow;
    private final boolean fetch_node_index;
    private final boolean distributed_metadata;
    private final TorusKeyType key_type;

    public GetPubKeyOrKeyAssignRequestParams(String _verifier, String _verifier_id, String _extended_verifier_id, TorusKeyType key_type, boolean _one_key_flow,
                                             boolean _fetch_node_index, boolean distributed_metadata) {
        verifier = _verifier;
        verifier_id = _verifier_id;
        this.extended_verifier_id = _extended_verifier_id;
        this.key_type = key_type;
        this.one_key_flow = _one_key_flow;
        this.fetch_node_index = _fetch_node_index;
        this.distributed_metadata = distributed_metadata;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getVerifier_id() {
        return verifier_id;
    }

    public String getExtendedVerifierId() {
        return extended_verifier_id;
    }

    public boolean isOne_key_flow() {
        return one_key_flow;
    }

    public boolean isFetch_node_index() {
        return fetch_node_index;
    }

    public boolean isDistributed_metadata() {
        return distributed_metadata;
    }

    public TorusKeyType getKeyType() {
        return key_type;
    }
}
