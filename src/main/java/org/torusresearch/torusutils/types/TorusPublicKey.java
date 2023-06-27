package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.Nullable;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;

import java.math.BigInteger;
import java.util.List;

public class TorusPublicKey extends TorusNodePub {
    private final String address;
    private TypeOfUser typeOfUser;
    private BigInteger metadataNonce;
    @Nullable
    private GetOrSetNonceResult.PubNonce pubNonce;
    private boolean upgraded;
    private List<Integer> nodeIndexes;

    public TorusPublicKey(String _X, String _Y, String _address) {
        super(_X, _Y);
        address = _address;
    }

    public TorusPublicKey(String _address) {
        super(null, null);
        address = _address;
    }

    public TorusPublicKey(String _address, String _X, String _Y, BigInteger _metadataNonce, GetOrSetNonceResult.PubNonce _pubNonce,
                          boolean _upgraded, List<Integer> _nodeIndexes, TypeOfUser _typeOfUser) {
        super(_X, _Y);
        address = _address;
        metadataNonce = _metadataNonce;
        pubNonce = _pubNonce;
        upgraded = _upgraded;
        nodeIndexes = _nodeIndexes;
        typeOfUser = _typeOfUser;
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

    public boolean getUpgraded() {
        return upgraded;
    }

    public void setUpgraded(boolean upgraded) {
        this.upgraded = upgraded;
    }

    public List<Integer> getNodeIndexes() {
        return nodeIndexes;
    }

    public void setNodeIndexes(List<Integer> nodeIndexes) {
        this.nodeIndexes = nodeIndexes;
    }
}
