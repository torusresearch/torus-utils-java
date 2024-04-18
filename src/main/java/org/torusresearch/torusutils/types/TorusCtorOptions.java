package org.torusresearch.torusutils.types;

import org.torusresearch.fetchnodedetails.types.TorusNetwork;

import java.math.BigInteger;

import static org.torusresearch.fetchnodedetails.types.Utils.METADATA_MAP;
import static org.torusresearch.fetchnodedetails.types.Utils.SIGNER_MAP;

public class TorusCtorOptions {
    private String legacyMetadataHost;
    private String allowHost;
    private String signerHost;
    // in seconds
    private BigInteger serverTimeOffset = new BigInteger("0");
    private String origin;
    private TorusNetwork network;
    private String clientId;
    private boolean enableOneKey = false;

    public TorusCtorOptions(String origin, String clientId, TorusNetwork network) {
        this.origin = origin;
        this.clientId = clientId;
        this.network = network;
        this.legacyMetadataHost = METADATA_MAP.get(network);
        this.allowHost = SIGNER_MAP.get(network) + "/api/allow";
        this.signerHost = SIGNER_MAP.get(network) + "/api/sign";
    }

    public TorusNetwork getNetwork() {
        return network;
    }

    public void setNetwork(TorusNetwork network) {
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
}
