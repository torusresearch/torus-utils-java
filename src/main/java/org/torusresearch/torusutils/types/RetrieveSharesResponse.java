package org.torusresearch.torusutils.types;

public class RetrieveSharesResponse {
    private final String ethAddress;
    private final String privKey;

    public RetrieveSharesResponse(String _ethAddress, String _privKey) {
        ethAddress = _ethAddress;
        privKey = _privKey;
    }

    public String getEthAddress() {
        return ethAddress;
    }

    public String getPrivKey() {
        return privKey;
    }
}
