package org.torusresearch.torusutils.helpers;

import java.util.concurrent.CompletionException;

public class PredicateFailedException extends CompletionException {
    public PredicateFailedException(String errMessage) {
        super(errMessage);
    }
}
