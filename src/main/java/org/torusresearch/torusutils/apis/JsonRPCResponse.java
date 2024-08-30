package org.torusresearch.torusutils.apis;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;


public class JsonRPCResponse<T> {

    private final JsonRPCErrorInfo error;
    public final T result;


    public JsonRPCErrorInfo getError() {
        return error;
    }

    public T getTypedResult(Class<T> clazz) {
        Gson gson = new Gson();
        return gson.fromJson(gson.toJson(result), TypeToken.get(clazz).getType());
    }

    public JsonRPCResponse(JsonRPCErrorInfo error, T result) {
        this.error = error;
        this.result = result;
    }
}
