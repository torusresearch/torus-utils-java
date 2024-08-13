package org.torusresearch.torusutils.types;

import java.util.List;

public class NodesData {

    public List<Integer> nodeIndexes;

    public NodesData(List<Integer> nodeIndexes) {
        this.nodeIndexes = nodeIndexes;
    }

    public List<Integer> getNodeIndexes() {
        return nodeIndexes;
    }

    public void setNodeIndexes(List<Integer> nodeIndexes) {
        this.nodeIndexes = nodeIndexes;
    }
}
