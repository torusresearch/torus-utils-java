package org.torusresearch.torusutils.types;

public class SetNonceData {

    private String data;

    private String operation;

    private String seed = "";
    private String timestamp;

    public SetNonceData(String operation, String timestamp) {
        this.operation = operation;
        this.timestamp = timestamp;
    }

    public SetNonceData(String operation, String data, String seed, String timestamp) {
        this.data = data;
        this.operation = operation;
        this.seed = seed;
        this.timestamp = timestamp;
    }

    public String getOperation() {
        return operation;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getSeed() {
        return seed;
    }
}
