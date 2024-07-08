package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class TorusCtorOptions {
    private String metadataHost = "https://metadata.tor.us";
    private String allowHost = "https://signer.tor.us/api/allow";
    private boolean enableOneKey = false;
    private String signerHost = "https://signer.tor.us/api/sign";
    // in seconds
    private BigInteger serverTimeOffset = new BigInteger("0");
    private String origin;
    private String network = "mainnet";

    private boolean legacyNonce = false;
    private String clientId;

    public TorusCtorOptions(String origin) {
        this.origin = origin;
    }

    public String getNetwork() {
        return network;
    }

    public void setNetwork(String network) {
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

    public String getSignerHost() {
        return signerHost;
    }

    public void setSignerHost(String signerHost) {
        this.signerHost = signerHost;
    }

    public boolean isEnableOneKey() {
        return enableOneKey;
    }

    public void setEnableOneKey(boolean enableOneKey) {
        this.enableOneKey = enableOneKey;
    }

    public String getAllowHost() {
        return allowHost;
    }

    public void setAllowHost(String allowHost) {
        this.allowHost = allowHost;
    }

    public String getMetadataHost() {
        return metadataHost;
    }

    public void setMetadataHost(String _metadataHost) {
        this.metadataHost = _metadataHost;
    }

    public boolean isLegacyNonce() {
        return legacyNonce;
    }

    public void setLegacyNonce(boolean legacyNonce) {
        this.legacyNonce = legacyNonce;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
