package org.torusresearch.torusutils.apis;

public class JRPCResponse<T> {
    private final int id;
    private final String jsonrpc;
    private final T result;
    private final JsonRPCErrorInfo error;

    public JRPCResponse(int id, String jsonrpc, T result, JsonRPCErrorInfo error) {
        this.id = id;
        this.jsonrpc = jsonrpc;
        this.result = result;
        this.error = error;
    }

    public int getId() {
        return id;
    }

    public String getJsonrpc() {
        return jsonrpc;
    }

    public T getResult() {
        return result;
    }

    public JsonRPCErrorInfo getError() {
        return error;
    }


}
