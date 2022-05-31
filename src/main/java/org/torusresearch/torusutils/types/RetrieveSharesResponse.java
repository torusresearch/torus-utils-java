package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class RetrieveSharesResponse {
    private final String ethAddress;
    private final BigInteger privKey;

    private final BigInteger nonce;

    public RetrieveSharesResponse(String _ethAddress, BigInteger _privKey, BigInteger _nonce) {
        ethAddress = _ethAddress;
        privKey = _privKey;
        nonce = _nonce;
    }

    public String getEthAddress() {
        return ethAddress;
    }

    public BigInteger getPrivKey() {
        return privKey;
    }

    public BigInteger getNonce() {
        return nonce;
    }
}
