package org.torusresearch.torusutils.apis;

import java.util.Random;

public class JsonRPCRequest {
    public final String jsonrpc;
    public final String method;
    public final Integer id;
    public final Object params;

    public JsonRPCRequest(String _method, Object _params) {
        jsonrpc = "2.0";
        method = _method;
        id = new Random().nextInt(1000);
        params = _params;
    }
}
