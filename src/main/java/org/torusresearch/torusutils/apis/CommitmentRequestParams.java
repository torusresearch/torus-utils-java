package org.torusresearch.torusutils.apis;

public class CommitmentRequestParams {
    private final String messageprefix;
    private final String tokencommitment;
    private final String temppubx;
    private final String temppuby;
    private final String timestamp;
    private final String verifieridentifier;

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
