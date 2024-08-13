package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.apis.responses.PubNonce;

import java.math.BigInteger;

public class Metadata {

    public PubNonce pubNonce;
    public BigInteger nonce;
    public boolean upgraded;
    public TypeOfUser typeOfUser;

    public Integer serverTimeOffset;

    public Metadata(PubNonce pubNonce, BigInteger nonce, TypeOfUser typeOfUser, boolean upgraded, Integer serverTimeOffset) {
        this.pubNonce = pubNonce;
        this.nonce = nonce;
        this.typeOfUser = typeOfUser;
        this.upgraded = upgraded;
        this.serverTimeOffset = serverTimeOffset;
    }

    public Metadata(PubNonce pubNonce, BigInteger nonce, TypeOfUser typeOfUser, boolean upgraded) {
        this.pubNonce = pubNonce;
        this.nonce = nonce;
        this.typeOfUser = typeOfUser;
        this.upgraded = upgraded;
    }

    public PubNonce getPubNonce() {
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

    public Integer getServerTimeOffset() {
        return serverTimeOffset;
    }
}
