package org.torusresearch.torusutils.types;

public class VerifierArgs {
    private final String verifier;
    private final String verifierId;

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
