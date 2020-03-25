package org.torusresearch.torusutils.apis;

import com.google.gson.Gson;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CompletableFuture;

public class APIUtils {
    private APIUtils() {
    }

    public static String generateJsonRPCObject(String method, Object params) {
        Gson gson = new Gson();
        return gson.toJson(new JsonRPCCall(method, params));
    }

    public static CompletableFuture<String> post(String url, String data) {
        return _post(url, data, new Header[0]);
    }

    public static CompletableFuture<String> post(String url, String data, Header[] headers) {
        return _post(url, data, headers);
    }

    private static CompletableFuture<String> _post(String url, String data, Header[] headers) {
        CloseableHttpAsyncClient httpClient = HttpAsyncClients.createDefault();
        httpClient.start();
        HttpPost request = new HttpPost(url);
        request.addHeader("Content-Type", "application/json; charset=utf-8");
        for (int i = 0; i < headers.length; i++) {
            request.addHeader(headers[i]);
        }
        request.setEntity(new StringEntity(data, StandardCharsets.UTF_8));
        CompletableFuture completableFuture = new CompletableFuture();
        TimerTask task = new TimerTask() {
            public void run() {
                if (!completableFuture.isDone()) {
                    request.abort();
                }
            }
        };
        new Timer(true).schedule(task, 12000);
        httpClient.execute(request, new FutureCallback<HttpResponse>() {
            public void completed(HttpResponse httpResponse) {
                System.out.println("completed post");
                try {
                    completableFuture.complete(EntityUtils.toString(httpResponse.getEntity()));
                } catch (IOException e) {
                    System.out.println("IO EXCEPTION");
                    completableFuture.completeExceptionally(e);
                }
                try {
                    httpClient.close();
                } catch (Exception e) {
                    System.out.println("EXCEPTION");
                    e.printStackTrace();
                }
            }

            public void failed(Exception exception) {
                System.out.println("failed post");
                completableFuture.completeExceptionally(exception);
                try {
                    httpClient.close();
                } catch (IOException e) {
                    System.out.println("IO EXCEPTION");
                    e.printStackTrace();
                }
            }

            public void cancelled() {
                System.out.println("cancelled post");
                completableFuture.completeExceptionally(new Exception("canceled request"));
                try {
                    httpClient.close();
                } catch (IOException e) {
                    System.out.println("IO EXCEPTION");
                    e.printStackTrace();
                }
            }
        });
        return completableFuture;
    }
}
