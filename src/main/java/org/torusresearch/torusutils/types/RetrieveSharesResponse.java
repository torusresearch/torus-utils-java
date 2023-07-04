package org.torusresearch.torusutils.types;

public class RetrieveSharesResponse {
    /*private final String ethAddress;
    private final BigInteger privKey;

    private final BigInteger nonce;
    private List<SessionToken> sessionTokens;
    private String X;
    private String Y;
    private String postboxPubKeyX;
    private String postboxPubKeyY;
    private String sessionAuthKey;
    private List<BigInteger> nodeIndexes;


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

    public RetrieveSharesResponse(String _ethAddress, BigInteger _privKey, BigInteger _nonce) {
        ethAddress = _ethAddress;
        privKey = _privKey;
        nonce = _nonce;
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
*/
    public FinalKeyData finalKeyData;
    public OAuthKeyData oAuthKeyData;
    public SessionData sessionData;
    public Metadata metadata;
    public NodesData nodesData;

    public RetrieveSharesResponse(FinalKeyData finalKeyData, OAuthKeyData oAuthKeyData, SessionData sessionData, Metadata metadata, NodesData nodesData) {
        this.finalKeyData = finalKeyData;
        this.oAuthKeyData = oAuthKeyData;
        this.sessionData = sessionData;
        this.metadata = metadata;
        this.nodesData = nodesData;
    }

    public FinalKeyData getFinalKeyData() {
        return finalKeyData;
    }

    public OAuthKeyData getoAuthKeyData() {
        return oAuthKeyData;
    }

    public SessionData getSessionData() {
        return sessionData;
    }

    public Metadata getMetadata() {
        return metadata;
    }

    public NodesData getNodesData() {
        return nodesData;
    }
}
