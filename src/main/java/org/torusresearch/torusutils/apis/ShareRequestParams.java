package org.torusresearch.torusutils.apis;

public class ShareRequestParams {
    private final ShareRequestItem[] item;
    private final String encrypted;

    public ShareRequestParams(ShareRequestItem[] _item) {
        item = _item;
        encrypted = "yes";
    }

    public ShareRequestItem[] getItem() {
        return item;
    }
}
