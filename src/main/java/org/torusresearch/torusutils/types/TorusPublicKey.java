package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.Nullable;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;

import java.math.BigInteger;

public class TorusPublicKey extends TorusNodePub {
    private final String address;
    private TypeOfUser typeOfUser;
    private BigInteger metadataNonce;
    @Nullable
    private GetOrSetNonceResult.PubNonce pubNonce;

    public TorusPublicKey(String _X, String _Y, String _address) {
        super(_X, _Y);
        address = _address;
    }

    public TorusPublicKey(String _address) {
        super(null, null);
        address = _address;
    }

    public String getAddress() {
        return address;
    }

    public TypeOfUser getTypeOfUser() {
        return typeOfUser;
    }

    public void setTypeOfUser(TypeOfUser typeOfUser) {
        this.typeOfUser = typeOfUser;
    }

    public BigInteger getMetadataNonce() {
        return metadataNonce;
    }

    public void setMetadataNonce(BigInteger metadataNonce) {
        this.metadataNonce = metadataNonce;
    }

    public GetOrSetNonceResult.PubNonce getPubNonce() {
        return pubNonce;
    }

    public void setPubNonce(GetOrSetNonceResult.PubNonce pubNonce) {
        this.pubNonce = pubNonce;
    }
}
