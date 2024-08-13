package org.torusresearch.torusutils.apis;

import java.util.Random;

public class JsonRPCRequest {
    private final String jsonrpc;
    private final String method;
    private final Integer id;
    private final Object params;

    public JsonRPCRequest(String _method, Object _params) {
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

    public static class JRPCResponse<T> {
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
}
