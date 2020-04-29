package org.torusresearch.torusutils.apis;

public class JsonRPCResponse {
    private final JsonRPCError error;
    private final Object result;


    public JsonRPCError getError() {
        return error;
    }

    public Object getResult() {
        return result;
    }

    public JsonRPCResponse(JsonRPCError _error, Object _result) {
        error = _error;
        result = _result;
    }
}
