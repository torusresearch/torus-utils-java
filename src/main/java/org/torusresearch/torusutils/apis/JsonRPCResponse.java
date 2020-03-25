package org.torusresearch.torusutils.apis;

public class JsonRPCResponse {
    private JsonRPCError error;
    private Object result;


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
