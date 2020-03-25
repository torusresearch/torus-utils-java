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

    public String getTokencommitment() {
        return tokencommitment;
    }

    public String getTemppubx() {
        return temppubx;
    }

    public String getTemppuby() {
        return temppuby;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getVerifieridentifier() {
        return verifieridentifier;
    }
}
