package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.Nullable;

public class GetOrSetNonceResult {
    private String ipfs;
    @Nullable
    private String nonce;
    @Nullable
    private PubNonce pubNonce;
    private boolean upgraded;
    private final TypeOfUser typeOfUser;

    public GetOrSetNonceResult(TypeOfUser typeOfUser) {
        this.typeOfUser = typeOfUser;
    }

    @Nullable
    public String getNonce() {
        return nonce;
    }

    public void setNonce(@Nullable String nonce) {
        this.nonce = nonce;
    }

    @Nullable
    public PubNonce getPubNonce() {
        return pubNonce;
    }

    public void setPubNonce(@Nullable PubNonce pubNonce) {
        this.pubNonce = pubNonce;
    }

    public boolean isUpgraded() {
        return upgraded;
    }

    public void setUpgraded(boolean upgraded) {
        this.upgraded = upgraded;
    }

    public String getIpfs() {
        return ipfs;
    }

    public void setIpfs(String ipfs) {
        this.ipfs = ipfs;
    }

    public TypeOfUser getTypeOfUser() {
        return typeOfUser;
    }

    public static class PubNonce {
        private final String x;
        private final String y;

        public PubNonce(String x, String y) {
            this.x = x;
            this.y = y;
        }

        public String getX() {
            return x;
        }

        public String getY() {
            return y;
        }
    }
}
