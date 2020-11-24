package org.torusresearch.torusutils.apis;

import java.util.HashMap;
import java.util.List;

public class ShareRequestParams {
    private final String encrypted;
    private final List<HashMap<String, Object>> item;

    public ShareRequestParams(List<HashMap<String, Object>> _item) {
        encrypted = "yes";
        item = _item;
    }

    public List<HashMap<String, Object>> getItem() {
        return item;
    }
}
