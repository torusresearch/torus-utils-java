package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class DecryptedShare {
    private final BigInteger index;
    private final BigInteger value;

    public DecryptedShare(BigInteger _index, BigInteger _value) {
        index = _index;
        value = _value;
    }

    public BigInteger getIndex() {
        return index;
    }

    public BigInteger getValue() {
        return value;
    }
}
