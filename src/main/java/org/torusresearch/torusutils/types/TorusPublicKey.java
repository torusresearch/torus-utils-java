package org.torusresearch.torusutils.types;

import org.torusresearch.fetchnodedetails.types.TorusNodePub;

public class TorusPublicKey extends TorusNodePub {
    private final String address;

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
