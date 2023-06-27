package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class PrivateKeyWithNonceResult {

    private BigInteger privateKey;
    private GetOrSetNonceResult nonceResult;

    public PrivateKeyWithNonceResult(BigInteger _privateKey, GetOrSetNonceResult _nonceResult) {
        this.privateKey = _privateKey;
        this.nonceResult = _nonceResult;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }
}
