package org.torusresearch.torusutils.types;

import static org.torusresearch.fetchnodedetails.types.Utils.METADATA_MAP;
import static org.torusresearch.fetchnodedetails.types.Utils.SIGNER_MAP;

import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;

import java.math.BigInteger;

public class TorusCtorOptions {
    private String legacyMetadataHost;
    private String allowHost;
    private String signerHost;
    // in seconds
    private BigInteger serverTimeOffset = new BigInteger("0");
    private String origin;
    private Web3AuthNetwork network;
    private String clientId;
    private boolean enableOneKey = false;
    private KeyType keyType = KeyType.secp256k1;

    public TorusCtorOptions(String origin, String clientId, Web3AuthNetwork network) {
        this.origin = origin;
        this.clientId = clientId;
        this.network = network;
        this.legacyMetadataHost = METADATA_MAP.get(network);
        this.allowHost = SIGNER_MAP.get(network) + "/api/allow";
        this.signerHost = SIGNER_MAP.get(network) + "/api/sign";
        this.serverTimeOffset = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        //this.keyType = keyType;
    }

    public Web3AuthNetwork getNetwork() {
        return network;
    }

    public void setNetwork(Web3AuthNetwork network) {
        this.network = network;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public BigInteger getServerTimeOffset() {
        return serverTimeOffset;
    }

    public void setServerTimeOffset(BigInteger serverTimeOffset) {
        this.serverTimeOffset = serverTimeOffset;
    }

    public String getAllowHost() {
        return allowHost;
    }

    public void setAllowHost(String allowHost) {
        this.allowHost = allowHost;
    }

    public String getSignerHost() { return signerHost; }

    public void setSignerHost(String signerHost) { this.signerHost = signerHost; }

    public String getLegacyMetadataHost() {
        return legacyMetadataHost;
    }

    public void setLegacyMetadataHost(String _metadataHost) {
        this.legacyMetadataHost = _metadataHost;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public boolean isEnableOneKey() {
        return enableOneKey;
    }

    public void setEnableOneKey(boolean enableOneKey) {
        this.enableOneKey = enableOneKey;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

}
