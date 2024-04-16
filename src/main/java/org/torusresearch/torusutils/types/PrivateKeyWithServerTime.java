package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class PrivateKeyWithServerTime {
    private BigInteger privateKey;
    private BigInteger serverTimeOffset;

    public PrivateKeyWithServerTime(BigInteger _privateKey, BigInteger serverTimeOffset) {
        this.privateKey = _privateKey;
        this.serverTimeOffset = serverTimeOffset;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getServerTimeOffset() {
        return serverTimeOffset;
    }
}
