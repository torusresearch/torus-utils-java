package org.torusresearch.torusutils.types;

import java.util.Optional;

public class KeyAssignment {
    private KeyIndex index;
    private PublicKey publicKey;
    private int threshold;
    private int nodeIndex;
    private String share;
    private EciesHex shareMetadata;
    private Optional<GetOrSetNonceResult> nonceData;

    public KeyIndex getIndex() {
        return index;
    }

    public void setIndex(KeyIndex index) {
        this.index = index;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public int getThreshold() {
        return threshold;
    }

    public void setThreshold(int threshold) {
        this.threshold = threshold;
    }

    public int getNodeIndex() {
        return nodeIndex;
    }

    public void setNodeIndex(int nodeIndex) {
        this.nodeIndex = nodeIndex;
    }

    public String getShare() {
        return share;
    }

    public void setShare(String share) {
        this.share = share;
    }

    public EciesHex getShareMetadata() {
        return shareMetadata;
    }

    public void setShareMetadata(EciesHex shareMetadata) {
        this.shareMetadata = shareMetadata;
    }

    public Optional<GetOrSetNonceResult> getNonceData() {
        return nonceData;
    }

    public void setNonceData(Optional<GetOrSetNonceResult> nonceData) {
        this.nonceData = nonceData;
    }
}


