package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.types.KeyInfo;

import java.util.List;

public class KeysRPCResponse {

    private boolean isNewKey;

    private List<KeyInfo> keys;

    private String serverTimeOffset;

    public KeysRPCResponse(List<KeyInfo> keys, boolean isNewKey, String serverTimeOffset) {
        this.keys = keys;
        this.isNewKey = isNewKey;
        this.serverTimeOffset = serverTimeOffset;
    }

    public List<KeyInfo> getKeys() {
        return keys;
    }

    public boolean isNewKey() {
        return isNewKey;
    }

    public String getServerTimeOffset() {
        return serverTimeOffset;
    }
}
