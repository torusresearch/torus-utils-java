package org.torusresearch.torusutils.apis;

public class NodeSignature {
    private final String signature;
    private final String data;
    private final String nodepubx;
    private final String nodepuby;
    private final String nodeindex;

    public NodeSignature(String _signature, String _data, String _nodepubx, String _nodepuby, String _nodeindex) {
        signature = _signature;
        data = _data;
        nodepubx = _nodepubx;
        nodepuby = _nodepuby;
        nodeindex = _nodeindex;
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

    public String getNodeindex() {
        return nodeindex;
    }
}
