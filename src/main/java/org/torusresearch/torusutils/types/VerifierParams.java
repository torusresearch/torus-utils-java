package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.apis.VerifyParams;

public class VerifierParams {
    private String verifierId;
    private String extendedVerifierId;
    private String[] subVerifierIds;
    private VerifyParams[] verifyParams;

    public String getVerifierId() {
        return verifierId;
    }

    public void setVerifierId(String verifierId) {
        this.verifierId = verifierId;
    }

    public String getExtendedVerifierId() {
        return extendedVerifierId;
    }

    public void setExtendedVerifierId(String extendedVerifierId) {
        this.extendedVerifierId = extendedVerifierId;
    }

    public String[] getSubVerifierIds() {
        return subVerifierIds;
    }

    public void setSubVerifierIds(String[] subVerifierIds) {
        this.subVerifierIds = subVerifierIds;
    }

    public VerifyParams[] getVerifyParams() {
        return verifyParams;
    }

    public void setVerifyParams(VerifyParams[] verifyParams) {
        this.verifyParams = verifyParams;
    }
}

