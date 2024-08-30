package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;

import java.util.List;

public class NodesData {

    private final List<Integer> nodeIndexes;

    public NodesData(@NotNull List<Integer> nodeIndexes) {
        this.nodeIndexes = nodeIndexes;
    }

    public List<Integer> getNodeIndexes() {
        return nodeIndexes;
    }
}
