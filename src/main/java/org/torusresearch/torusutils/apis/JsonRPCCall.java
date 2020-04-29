package org.torusresearch.torusutils.apis;

import java.util.Random;

public class JsonRPCCall {
    private final String jsonrpc;
    private final String method;
    private final Integer id;
    private final Object params;

    public JsonRPCCall(String _method, Object _params) {
        jsonrpc = "2.0";
        method = _method;
        id = new Random().nextInt(1000);
        params = _params;
    }

    public String getJsonrpc() {
        return jsonrpc;
    }

    public String getMethod() {
        return method;
    }

    public Integer getId() {
        return id;
    }

    public Object getParams() {
        return params;
    }
}
