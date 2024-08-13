package org.torusresearch.torusutils.apis;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class JsonRPCResponse<T> {
    private final JsonRPCRequest.JRPCResponse.ErrorInfo error;
    public final T result;


    public JsonRPCRequest.JRPCResponse.ErrorInfo getError() {
        return error;
    }

    public T getTypedResult(Class<T> clazz) {
        Gson gson = new Gson();
        TypeToken type = TypeToken.get(clazz);
        return gson.fromJson(gson.toJson(result), type.getType());
    }

    public JsonRPCResponse(JsonRPCRequest.JRPCResponse.ErrorInfo error, T result) {
        this.error = error;
        this.result = result;
    }
}
