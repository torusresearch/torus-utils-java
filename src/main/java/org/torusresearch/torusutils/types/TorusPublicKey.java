package org.torusresearch.torusutils.types;

public class TorusPublicKey extends TorusNodePub {
    private String address;
    public TorusPublicKey(String _X, String _Y, String _address) {
        super(_X, _Y);
        address = _address;
    }
    public TorusPublicKey(String _address) {
        super(null, null);
        address = _address;
    }

    public String getAddress() {
        return address;
    }
}
