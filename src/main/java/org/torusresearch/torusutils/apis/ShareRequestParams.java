package org.torusresearch.torusutils.apis;

import java.util.HashMap;
import java.util.List;

public class ShareRequestParams {
    private final String encrypted;
    private final boolean one_key_flow;
    private final boolean use_temp;
    private final boolean distributed_metadata;
    private final String client_time;
    private final List<HashMap<String, Object>> item;

    public ShareRequestParams(List<HashMap<String, Object>> _item) {
        encrypted = "yes";
        one_key_flow = true;
        use_temp = true;
        distributed_metadata = true;
        item = _item;
        client_time = Long.toString(System.currentTimeMillis() / 1000);
    }

    public List<HashMap<String, Object>> getItem() {
        return item;
    }
}
