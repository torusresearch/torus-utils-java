package org.torusresearch.torusutils.apis;

public class JsonRPCError {
    private final int code;
    private final String message;
    private final String data;

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public String getData() {
        return data;
    }

    public JsonRPCError(int _code, String _message, String _data) {
        code = _code;
        message = _message;
        data = _data;
    }

}
