package org.torusresearch.torusutils.apis;

public class KeyAssignParams {
    private String verifier;
    private String verifier_id;

    public String getVerifier() {
        return verifier;
    }

    public String getVerifier_id() {
        return verifier_id;
    }

    public KeyAssignParams(String _verifier, String _verifier_id) {
        verifier = _verifier;
        verifier_id = _verifier_id;
    }

}
