package org.torusresearch.torusutils.apis;

public class VerifierLookupRequestParams {
    private final String verifier;
    private final String verifier_id;

    public VerifierLookupRequestParams(String _verifier, String _verifier_id) {
        verifier = _verifier;
        verifier_id = _verifier_id;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getVerifier_id() {
        return verifier_id;
    }
}
