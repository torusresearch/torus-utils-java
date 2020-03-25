package org.torusresearch.torusutils.apis;

public class ShareRequestParams {
    private ShareRequestItem[] item;
    private String encrypted;
    public ShareRequestParams(ShareRequestItem[] _item) {
        item = _item;
        encrypted = "yes";
    }
    public ShareRequestItem[] getItem() {
        return item;
    }
}
