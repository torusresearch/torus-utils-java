package org.torusresearch.torusutils.types;

import com.google.gson.Gson;

public class SomeException extends Exception {
    public String[] errors;

    public String[] responses;

    public String  predicate;

    public SomeException(String[] errors ,String[] responses, String predicate) {
        super("Unable to resolve enough promises.");
        this.errors = errors;
        this.responses = responses;
        this.predicate = predicate;
    }

    @Override
    public String toString() {
        Gson gson = new Gson();
        return gson.toJson(this.errors) + ", responses: " +
                gson.toJson(this.responses) + this.predicate;
    }
}