package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.TypeOfUser;

import java.math.BigInteger;

import io.reactivex.annotations.Nullable;

public class Metadata {

    public PubNonce pubNonce;
    public BigInteger nonce;
    @Nullable
    public Boolean upgraded;
    public TypeOfUser typeOfUser;

    public Integer serverTimeOffset;

    public Metadata(PubNonce pubNonce, BigInteger nonce, TypeOfUser typeOfUser, @Nullable Boolean upgraded, Integer serverTimeOffset) {
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
