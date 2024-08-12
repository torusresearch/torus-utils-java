package org.torusresearch.torusutils.apis;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;

public class JsonRPCResponse<T> {
    private final JsonRPCError error;
    public final T result;


    public JsonRPCError getError() {
        return error;
    }

    public T getResult() {
        return result;
    }

    public T getTypedResult(Class<T> clazz) {
        Gson gson = new Gson();
        TypeToken type = TypeToken.get(clazz);
        return gson.fromJson(gson.toJson(result), type.getType());
    }

    public JsonRPCResponse(JsonRPCError error, T result) {
        this.error = error;
        this.result = result;
    }
}
