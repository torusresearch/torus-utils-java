package org.torusresearch.torusutils.apis;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.torusresearch.torusutils.types.JRPCResponse;

public class JsonRPCResponse<T> {
    private final JRPCResponse.ErrorInfo error;
    public final T result;


    public JRPCResponse.ErrorInfo getError() {
        return error;
    }

    // TODO: Remove this function
    public T getResult() {
        return result;
    }

    public T getTypedResult(Class<T> clazz) {
        Gson gson = new Gson();
        TypeToken type = TypeToken.get(clazz);
        return gson.fromJson(gson.toJson(result), type.getType());
    }

    public JsonRPCResponse(JRPCResponse.ErrorInfo error, T result) {
        this.error = error;
        this.result = result;
    }
}
