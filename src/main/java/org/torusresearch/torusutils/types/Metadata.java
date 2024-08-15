package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.TypeOfUser;

import java.math.BigInteger;

import io.reactivex.annotations.Nullable;

public class Metadata {

    private final PubNonce pubNonce;
    private final BigInteger nonce;
    @Nullable
    private final Boolean upgraded;
    private final TypeOfUser typeOfUser;

    private final Integer serverTimeOffset;

    public Metadata(@NotNull PubNonce pubNonce, @NotNull BigInteger nonce, @NotNull TypeOfUser typeOfUser, @Nullable Boolean upgraded, @NotNull Integer serverTimeOffset) {
        this.pubNonce = pubNonce;
        this.nonce = nonce;
        this.typeOfUser = typeOfUser;
        this.upgraded = upgraded;
        this.serverTimeOffset = serverTimeOffset;
    }

    public Metadata(@NotNull PubNonce pubNonce, @NotNull BigInteger nonce, @NotNull TypeOfUser typeOfUser, @NotNull Boolean upgraded) {
        this.pubNonce = pubNonce;
        this.nonce = nonce;
        this.typeOfUser = typeOfUser;
        this.upgraded = upgraded;
        this.serverTimeOffset = 0;
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
