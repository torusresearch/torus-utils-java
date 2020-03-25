package org.torusresearch.torusutils.types;

public class VerifierArgs {
    private String verifier;
    private String verifierId;
    public VerifierArgs(String _verifier, String _verifierId) {
        verifier = _verifier;
        verifierId = _verifierId;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getVerifierId() {
        return verifierId;
    }
}
