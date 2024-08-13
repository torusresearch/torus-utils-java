package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.helpers.TorusUtilError;

import java.math.BigInteger;

public class Share {
    private final BigInteger share;
    private final BigInteger shareIndex;

    public Share(String shareIndex, String share) throws Exception {
        // Initialize shareIndex and share from hexadecimal strings
        try {
            this.shareIndex = new BigInteger(shareIndex, 16);
        } catch (NumberFormatException e) {
            throw new TorusUtilError("Invalid input");
        }

        try {
            this.share = new BigInteger(share, 16);
        } catch (NumberFormatException e) {
            throw new TorusUtilError("Invalid input");
        }
    }

    public Share(BigInteger shareIndex, BigInteger share) {
        this.shareIndex = shareIndex;
        this.share = share;
    }

    public BigInteger getShare() {
        return share;
    }

    public BigInteger getShareIndex() {
        return shareIndex;
    }

    // toString method for debugging purposes
    @Override
    public String toString() {
        return "Share{" +
                "share=" + share.toString(16) +
                ", shareIndex=" + shareIndex.toString(16) +
                '}';
    }
}
