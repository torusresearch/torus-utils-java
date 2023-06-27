package org.torusresearch.torusutils.types;

import java.math.BigInteger;
import java.util.List;

public class RetrieveSharesResponse {
    private final String ethAddress;
    private final BigInteger privKey;

    private final BigInteger nonce;
    private final List<SessionToken> sessionTokens;
    private final String X;
    private final String Y;
    private final String postboxPubKeyX;
    private final String postboxPubKeyY;
    private final String sessionAuthKey;
    private final List<BigInteger> nodeIndexes;


    public RetrieveSharesResponse(String _ethAddress, BigInteger _privKey, BigInteger _nonce, List<SessionToken> _sessionTokens,
                                  String _x, String _y, String _postboxPubKeyX, String _postboxPubKeyY, String _sessionAuthKey, List<BigInteger> _nodeIndexes) {
        ethAddress = _ethAddress;
        privKey = _privKey;
        nonce = _nonce;
        this.sessionTokens = _sessionTokens;
        this.X = _x;
        this.Y = _y;
        this.postboxPubKeyX = _postboxPubKeyX;
        this.postboxPubKeyY = _postboxPubKeyY;
        this.sessionAuthKey = _sessionAuthKey;
        this.nodeIndexes = _nodeIndexes;
    }

    public String getEthAddress() {
        return ethAddress;
    }

    public BigInteger getPrivKey() {
        return privKey;
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public List<SessionToken> getSessionTokens() {
        return sessionTokens;
    }

    public String getX() {
        return X;
    }

    public String getY() {
        return Y;
    }

    public String getPostboxPubKeyX() {
        return postboxPubKeyX;
    }

    public String getPostboxPubKeyY() {
        return postboxPubKeyY;
    }

    public String getSessionAuthKey() {
        return sessionAuthKey;
    }

    public List<BigInteger> getNodeIndexes() {
        return nodeIndexes;
    }
}
