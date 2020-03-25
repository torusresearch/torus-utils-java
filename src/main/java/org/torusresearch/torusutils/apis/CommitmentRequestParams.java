package org.torusresearch.torusutils.apis;

public class CommitmentRequestParams {
    private String messageprefix;
    private String tokencommitment;
    private String temppubx;
    private String temppuby;
    private String timestamp;
    private String verifieridentifier;

    public CommitmentRequestParams(String _messageprefix, String _tokencommitment, String _temppubx, String _temppuby, String _timestamp, String _verifieridentifier) {
        messageprefix = _messageprefix;
        tokencommitment = _tokencommitment;
        temppubx = _temppubx;
        temppuby = _temppuby;
        timestamp = _timestamp;
        verifieridentifier = _verifieridentifier;
    }

    public String getMessageprefix() {
        return messageprefix;
    }

    public void setMessageprefix(String messageprefix) {
        this.messageprefix = messageprefix;
    }

    public String getTokencommitment() {
        return tokencommitment;
    }

    public void setTokencommitment(String tokencommitment) {
        this.tokencommitment = tokencommitment;
    }

    public String getTemppubx() {
        return temppubx;
    }

    public void setTemppubx(String temppubx) {
        this.temppubx = temppubx;
    }

    public String getTemppuby() {
        return temppuby;
    }

    public void setTemppuby(String temppuby) {
        this.temppuby = temppuby;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getVerifieridentifier() {
        return verifieridentifier;
    }

    public void setVerifieridentifier(String verifieridentifier) {
        this.verifieridentifier = verifieridentifier;
    }
}
