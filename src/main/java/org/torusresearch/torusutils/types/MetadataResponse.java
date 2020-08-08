package org.torusresearch.torusutils.types;

public class MetadataResponse {
    private final String message;

    public MetadataResponse(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
