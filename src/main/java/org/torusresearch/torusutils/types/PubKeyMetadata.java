package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class PubKeyMetadata {
    public GetOrSetNonceResult.PubNonce pubNonce;
    public BigInteger nonce;
    public boolean upgraded;
    public TypeOfUser typeOfUser;

    public PubKeyMetadata(GetOrSetNonceResult.PubNonce pubNonce, BigInteger nonce, boolean upgraded, TypeOfUser typeOfUser) {
        this.pubNonce = pubNonce;
        this.nonce = nonce;
        this.upgraded = upgraded;
        this.typeOfUser = typeOfUser;
    }

    public GetOrSetNonceResult.PubNonce getPubNonce() {
        return pubNonce;
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public boolean isUpgraded() {
        return upgraded;
    }

    public TypeOfUser getTypeOfUser() {
        return typeOfUser;
    }
}
