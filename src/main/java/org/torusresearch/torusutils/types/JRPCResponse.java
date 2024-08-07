package org.torusresearch.torusutils.types;

public class JRPCResponse<T> {
    private int id;
    private String jsonrpc;
    private T result;
    private ErrorInfo error;

    public JRPCResponse(int id, String jsonrpc, T result, ErrorInfo error) {
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

    public ErrorInfo getError() {
        return error;
    }

    public static class ErrorInfo {
        private int code;
        private String message;
        private Object data;

        public ErrorInfo(int code, String message, Object data) {
            this.code = code;
            this.message = message;
            this.data = data;
        }

        public int getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        public Object getData() {
            return data;
        }
    }
}
