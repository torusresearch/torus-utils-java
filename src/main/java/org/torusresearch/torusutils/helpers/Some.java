package org.torusresearch.torusutils.helpers;

import com.google.gson.Gson;
import java8.util.concurrent.CompletableFuture;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class Some<T> {
    private final AtomicInteger finishedCount = new AtomicInteger(0);
    private final String[] resultArr;
    private final String[] errorArr;
    private final CompletableFuture<T> completableFuture;
    private final AtomicBoolean resolved = new AtomicBoolean(false);
    private final AtomicReference<String> predicateError = new AtomicReference<>("");
    public Some(List<CompletableFuture<String>> promises, Predicate<T> predicate) {
        resultArr = new String[promises.size()];
        errorArr = new String[promises.size()];
        completableFuture = new CompletableFuture<>();
        for (int i = 0; i < promises.size(); i++) {
            int index = i;
            promises.get(index).thenComposeAsync((response) -> {
                resultArr[index] = response;
                if (resolved.get()) {
                    return null;
                }
                try {
                    T intermediateResult = predicate.call(resultArr.clone(), resolved).get();
                    resolved.set(true);
                    completableFuture.complete(intermediateResult);
                } catch (Exception e) {
                    predicateError.set(e.getMessage());
                    // swallow exceptions due to threshold assumptions
                }
                return null;
            }).exceptionally(e -> {
                errorArr[index] = e.getMessage();
                // swallow exceptions due to threshold assumptions
                int count = finishedCount.incrementAndGet();
                if (count == promises.size()) {
                    Gson gson = new Gson();
                    completableFuture.completeExceptionally(new Exception("Unable to resolve enough promises errors: " + gson.toJson(resultArr) + ", responses: " +
                            gson.toJson(errorArr) + ", predicate: " + predicateError.get()));
                }
                return null;
            });
        }
    }

    public CompletableFuture<T> getCompletableFuture() {
        return completableFuture;
    }
}
