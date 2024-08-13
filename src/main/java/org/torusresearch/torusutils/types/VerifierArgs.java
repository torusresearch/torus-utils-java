package org.torusresearch.torusutils.types;

// TODO: Refactor this out
public class VerifierArgs {
    private final String verifier;
    private final String verifierId;
    private String extendedVerifierId;

    public VerifierArgs(String _verifier, String _verifierId) {
        verifier = _verifier;
        verifierId = _verifierId;
    }

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
