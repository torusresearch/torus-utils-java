package org.torusresearch.torusutils.types;

import java.math.BigInteger;
import java.util.List;

public class NodesData {

    public List<BigInteger> nodeIndexes;

    public NodesData(List<BigInteger> nodeIndexes) {
        this.nodeIndexes = nodeIndexes;
    }

    public List<BigInteger> getNodeIndexes() {
        return nodeIndexes;
    }

    public void setNodeIndexes(List<BigInteger> nodeIndexes) {
        this.nodeIndexes = nodeIndexes;
    }
}
