package org.torusresearch.torusutils.apis;

import com.google.gson.Gson;
import java8.util.concurrent.CompletableFuture;
import okhttp3.*;
import okhttp3.internal.http2.Header;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.helpers.Utils;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class APIUtils {
    public static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final OkHttpClient client = new OkHttpClient().newBuilder().writeTimeout(12, TimeUnit.SECONDS).build();
    private static String apiKey;

    private APIUtils() {
    }

    public static String getApiKey() {
        return apiKey;
    }

    public static void setApiKey(String apiKey) {
        APIUtils.apiKey = apiKey;
    }

    public static String generateJsonRPCObject(String method, Object params) {
        Gson gson = new Gson();
        return gson.toJson(new JsonRPCCall(method, params));
    }

    public static Callback toCallback(CompletableFuture<String> future) {
        return new Callback() {
            @Override
            public void onFailure(@NotNull Call call, @NotNull IOException e) {
                future.completeExceptionally(e);
            }

            @Override
            public void onResponse(@NotNull Call call, @NotNull Response response) {
                try {
                    future.complete(Objects.requireNonNull(response.body()).string());
                } catch (IOException e) {
                    e.printStackTrace();
                    future.completeExceptionally(e);
                }
            }
        };
    }

    public static CompletableFuture<String> post(String url, String data, Boolean useApiKey) {
        return _post(url, data, new Header[0], useApiKey);
    }

    public static CompletableFuture<String> post(String url, String data, Header[] headers, Boolean useApiKey) {
        return _post(url, data, headers, useApiKey);
    }

    public static CompletableFuture<String> get(String url, Boolean useApiKey) {
        return _get(url, new Header[0], useApiKey);
    }

    public static CompletableFuture<String> get(String url, Header[] headers, Boolean useApiKey) {
        return _get(url, headers, useApiKey);
    }

    private static CompletableFuture<String> _post(String url, String data, Header[] headers, Boolean useApiKey) {
        RequestBody body = RequestBody.create(data, JSON);
        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .post(body);
        for (Header header : headers) {
            requestBuilder.addHeader(header.name.utf8(), header.value.utf8());
        }
        if (useApiKey && !Utils.isEmpty(apiKey))
            requestBuilder.addHeader("x-api-key", apiKey);
        Request request = requestBuilder.build();
        CompletableFuture<String> future = new CompletableFuture<>();
        client.newCall(request).enqueue(toCallback(future));
        return future;
    }

    private static CompletableFuture<String> _get(String url, Header[] headers, Boolean useApiKey) {
        Request.Builder requestBuilder = new Request.Builder().url(url);
        for (Header header : headers) {
            requestBuilder.addHeader(header.name.utf8(), header.value.utf8());
        }
        if (useApiKey && !Utils.isEmpty(apiKey))
            requestBuilder.addHeader("x-api-key", apiKey);
        Request request = requestBuilder.build();
        CompletableFuture<String> future = new CompletableFuture<>();
        client.newCall(request).enqueue(toCallback(future));
        return future;
    }
}
