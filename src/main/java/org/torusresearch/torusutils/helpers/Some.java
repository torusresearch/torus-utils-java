package org.torusresearch.torusutils.helpers;

import org.torusresearch.torusutils.types.SomeException;

import java.util.List;
import java.util.concurrent.CompletableFuture;
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
            promises.get(index).whenCompleteAsync((response, e) -> {
                int count = finishedCount.incrementAndGet();
                if (e != null) {
                    errorArr[index] = e.getMessage();
                    // swallow exceptions due to threshold assumptions
                    if (count == promises.size() && !completableFuture.isDone() && !resolved.get()) {
                        completableFuture.completeExceptionally(new SomeException(errorArr, resultArr, predicateError.get()));
                    }
                    return;
                }
                resultArr[index] = response;
                if (resolved.get()) {
                    return;
                }
                try {
                    T intermediateResult = predicate.call(resultArr.clone(), resolved).get();
                    resolved.set(true);
                    completableFuture.complete(intermediateResult);
                } catch (Exception e2) {
                    predicateError.set(e2.getMessage());
                    // swallow exceptions due to threshold assumptions
                    // if none of the predicates succeed, we throw at the end
                    if (count == promises.size() && !completableFuture.isDone() && !resolved.get()) {
                        completableFuture.completeExceptionally(new SomeException(errorArr, resultArr, predicateError.get()));
                    }
                }
            });
        }
    }

    public CompletableFuture<T> getCompletableFuture() {
        return completableFuture;
    }
}
