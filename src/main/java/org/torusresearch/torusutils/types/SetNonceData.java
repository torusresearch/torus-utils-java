package org.torusresearch.torusutils.types;

public class SetNonceData {

    private String operation;
    private String data;
    private String timestamp;

    public SetNonceData(String operation, String timestamp) {
        this.operation = operation;
        this.timestamp = timestamp;
    }

    public SetNonceData(String operation, String data, String timestamp) {
        this.operation = operation;
        this.data = data;
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
}
