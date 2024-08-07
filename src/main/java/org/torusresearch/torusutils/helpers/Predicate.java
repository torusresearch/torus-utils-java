package org.torusresearch.torusutils.helpers;

import java.util.concurrent.CompletableFuture;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

public interface Predicate<T> {
    CompletableFuture<T> call(String[] resultArr, AtomicBoolean resolved) throws PredicateFailedException, ExecutionException, InterruptedException;
}