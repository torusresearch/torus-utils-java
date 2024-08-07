package org.torusresearch.torusutils.apis;

public class VerifyParams {
    private final String idtoken;
    private final String verifier_id;

    public VerifyParams(String idtoken, String verifier_id) {
        this.idtoken = idtoken;
        this.verifier_id = verifier_id;
    }

    public String getVerifier_id() {
        return verifier_id;
    }

    public String getIdtoken() {
        return idtoken;
    }
}
