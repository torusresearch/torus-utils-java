package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class PrivateKeyWithNonceResult {

    private BigInteger privateKey;
    private GetOrSetNonceResult nonceResult;

    private BigInteger serverTimeOffsetResponse;

    public PrivateKeyWithNonceResult(BigInteger _privateKey, GetOrSetNonceResult _nonceResult, BigInteger serverTimeOffsetResponse) {
        this.privateKey = _privateKey;
        this.nonceResult = _nonceResult;
        this.serverTimeOffsetResponse = serverTimeOffsetResponse;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }

    public BigInteger getServerTimeOffsetResponse() {
        return serverTimeOffsetResponse;
    }
}
