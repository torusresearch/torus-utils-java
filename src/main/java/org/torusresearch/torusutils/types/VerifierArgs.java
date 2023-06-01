package org.torusresearch.torusutils.types;

public class VerifierArgs {
    private final String verifier;
    private final String verifierId;
    private final String extendedVerifierId;

    public VerifierArgs(String _verifier, String _verifierId, String _extendedVerifierId) {
        verifier = _verifier;
        verifierId = _verifierId;
        this.extendedVerifierId = _extendedVerifierId;
    }

    public String getVerifier() {
        return verifier;
    }

    public String getVerifierId() {
        return verifierId;
    }

    public String getExtendedVerifierId() {
        return extendedVerifierId;
    }
}
