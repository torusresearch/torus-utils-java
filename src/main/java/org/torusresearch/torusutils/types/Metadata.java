package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class Metadata {

    public GetOrSetNonceResult.PubNonce pubNonce;
    public BigInteger nonce;
    public boolean upgraded;
    public TypeOfUser typeOfUser;

    public BigInteger serverTimeOffset;

    public Metadata(GetOrSetNonceResult.PubNonce pubNonce, BigInteger nonce, TypeOfUser typeOfUser, boolean upgraded, BigInteger serverTimeOffset) {
        this.pubNonce = pubNonce;
        this.nonce = nonce;
        this.typeOfUser = typeOfUser;
        this.upgraded = upgraded;
        this.serverTimeOffset = serverTimeOffset;
    }

    public Metadata(GetOrSetNonceResult.PubNonce pubNonce, BigInteger nonce, TypeOfUser typeOfUser, boolean upgraded) {
        this.pubNonce = pubNonce;
        this.nonce = nonce;
        this.typeOfUser = typeOfUser;
        this.upgraded = upgraded;
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

    public BigInteger getServerTimeOffset() {
        return serverTimeOffset;
    }
}
