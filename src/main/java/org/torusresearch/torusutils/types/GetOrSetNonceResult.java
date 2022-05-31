package org.torusresearch.torusutils.types;


import org.jetbrains.annotations.Nullable;

public class GetOrSetNonceResult {
    private final TypeOfUser typeOfUser;
    @Nullable
    private String nonce;
    @Nullable
    private PubNonce pubNonce;
    private boolean upgraded;

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
