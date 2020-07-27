package org.torusresearch.torusutils.helpers;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

public class Some<T> {
    private final AtomicInteger finishedCount = new AtomicInteger(0);
    private boolean resolved = false;
    private final String[] resultArr;
    private final CompletableFuture<T> completableFuture;

    public Some(List<CompletableFuture<String>> promises, Predicate<T> predicate) {
        resultArr = new String[promises.size()];
        completableFuture = new CompletableFuture<>();
        for (int i = 0; i < promises.size(); i++) {
            int index = i;
            promises.get(index).thenComposeAsync((response) -> {
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
                }
                return null;
            }).exceptionally(e -> {
                // swallow exceptions due to threshold assumptions
                int count = finishedCount.incrementAndGet();
                if (count == promises.size()) {
                    completableFuture.completeExceptionally(new Exception("Unable to resolve enough promises"));
                }
                return null;
            });
        }
    }

    public CompletableFuture<T> getCompletableFuture() {
        return completableFuture;
    }
}
