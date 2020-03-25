package org.torusresearch.torusutils.apis;

public class NodeSignature {
    private String signature;
    private String data;
    private String nodepubx;
    private String nodepuby;

    public NodeSignature(String _signature, String _data, String _nodepubx, String _nodepuby) {
        signature = _signature;
        data = _data;
        nodepubx = _nodepubx;
        nodepuby = _nodepuby;
    }

    public String getSignature() {
        return signature;
    }

    public String getData() {
        return data;
    }

    public String getNodepubx() {
        return nodepubx;
    }

    public String getNodepuby() {
        return nodepuby;
    }
}
