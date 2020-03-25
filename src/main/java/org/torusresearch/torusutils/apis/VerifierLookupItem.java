package org.torusresearch.torusutils.apis;

public class VerifierLookupItem {
    private String key_index;
    private String pub_key_X;
    private String pub_key_Y;
    private String address;
    public String getKey_index() {
        return key_index;
    }

    public String getPub_key_X() {
        return pub_key_X;
    }

    public String getPub_key_Y() {
        return pub_key_Y;
    }

    public String getAddress() {
        return address;
    }

    public VerifierLookupItem(String _key_index, String _pub_key_X, String _pub_key_Y, String _address) {
        key_index = _key_index;
        pub_key_X = _pub_key_X;
        pub_key_Y = _pub_key_Y;
        address = _address;
    }

}
