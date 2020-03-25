package org.torusresearch.torusutils.helpers;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

public class Some<T>  {
    private AtomicInteger finishedCount = new AtomicInteger(0);
    private boolean resolved = false;
    private String[] resultArr;

    public CompletableFuture<T> getCompletableFuture() {
        return completableFuture;
    }

    private CompletableFuture<T> completableFuture;

    public Some(CompletableFuture<String>[] promises, Predicate<T> predicate) {
        resultArr = new String[promises.length];
        completableFuture = new CompletableFuture<T>();
        for (int i = 0; i < promises.length; i++) {
            int index = i;
            promises[index].thenComposeAsync((response) -> {
                resultArr[index] = response;
                if (resolved) {
                    return null;
                }
                try {
                    T intermediateResult = predicate.call(resultArr.clone()).get();
                    resolved = true;
                    completableFuture.complete(intermediateResult);
                } catch (Exception e) {
                    // swallow exceptions due to threshold assumptions
                    System.out.println(e);
                } finally {
                    return null;
                }
            }).exceptionally(e -> {
                // swallow exceptions due to threshold assumptions
                int count = finishedCount.incrementAndGet();
                if (count == promises.length) {
                    completableFuture.completeExceptionally(new Exception("Unable to resolve enough promises"));
                }
                return null;
            });
        }
    }
}
