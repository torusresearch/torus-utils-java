package org.torusresearch.torusutils.apis;

import com.google.gson.Gson;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.helpers.Common;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.ConnectionPool;
import okhttp3.Dispatcher;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.internal.http2.Header;

public class APIUtils {
    public static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final OkHttpClient client = new OkHttpClient().newBuilder()
            .writeTimeout(12, TimeUnit.SECONDS)
            .connectionPool(new ConnectionPool(64, 5, TimeUnit.SECONDS))
            .dispatcher(createDispatcher())
            .build();
    public static String apiKey;

    private static Dispatcher createDispatcher() {
        final Dispatcher dispatcher = new Dispatcher(Executors.newCachedThreadPool());
        dispatcher.setMaxRequests(64);
        dispatcher.setMaxRequestsPerHost(64);
        return dispatcher;
    }

    private APIUtils() {
    }

    public static void setApiKey(String apiKey) {
        APIUtils.apiKey = apiKey;
    }

    public static String generateJsonRPCObject(String method, Object params) {
        Gson gson = new Gson();
        return gson.toJson(new JsonRPCRequest(method, params));
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

    @SuppressWarnings("unused")
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
        if (useApiKey && !Common.isEmpty(apiKey))
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
        if (useApiKey && !Common.isEmpty(apiKey))
            requestBuilder.addHeader("x-api-key", apiKey);
        Request request = requestBuilder.build();
        CompletableFuture<String> future = new CompletableFuture<>();
        client.newCall(request).enqueue(toCallback(future));
        return future;
    }
}
