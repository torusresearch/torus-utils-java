package org.torusresearch.torusutils.helpers;

import java.util.concurrent.CompletableFuture;

public interface Predicate<T> {
    CompletableFuture<T> call(String[] resultArr) throws PredicateFailedException;
}