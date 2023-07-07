package org.torusresearch.torusutils.types;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class Share {
    private BigInteger share;
    private BigInteger shareIndex;

    public Share(BigInteger shareIndex, BigInteger share) {
        this.share = share;
        this.shareIndex = shareIndex;
    }

    public static Share fromJSON(Map<String, Object> value) {
        BigInteger share = (BigInteger) value.get("share");
        BigInteger shareIndex = (BigInteger) value.get("shareIndex");
        return new Share(shareIndex, share);
    }

    public Map<String, Object> toJSON() {
        Map<String, Object> json = new HashMap<>();
        json.put("share", share.toString(16));
        json.put("shareIndex", shareIndex.toString(16));
        return json;
    }

    public BigInteger getShare() {
        return share;
    }

    public BigInteger getShareIndex() {
        return shareIndex;
    }

    // Add getters and setters for share and shareIndex if needed
}
