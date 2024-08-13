package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;

import java.math.BigInteger;

public class PrivateKeyWithNonceResult {

    private BigInteger privateKey;
    private GetOrSetNonceResult nonceResult;

    private Integer serverTimeOffsetResponse;

    public PrivateKeyWithNonceResult(BigInteger _privateKey, GetOrSetNonceResult _nonceResult, Integer serverTimeOffsetResponse) {
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

    public Integer getServerTimeOffsetResponse() {
        return serverTimeOffsetResponse;
    }
}
