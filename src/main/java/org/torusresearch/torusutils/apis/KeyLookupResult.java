package org.torusresearch.torusutils.apis;

import org.torusresearch.torusutils.types.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.JRPCResponse;
import org.torusresearch.torusutils.types.VerifierLookupResponse;

import java.math.BigInteger;
import java.util.List;

public class KeyLookupResult {
    private final String keyResult;
    private List<BigInteger> nodeIndexes;
    private final String errResult;
    private JRPCResponse<VerifierLookupResponse> errorResult;
    private GetOrSetNonceResult nonceResult;
    private BigInteger server_time_offset;

    public KeyLookupResult(String _keyResult, String _errResult, List<BigInteger> nodeIndexes, GetOrSetNonceResult nonceResult, BigInteger server_time_offset) {
        keyResult = _keyResult;
        errResult = _errResult;
        this.nodeIndexes = nodeIndexes;
        this.nonceResult = nonceResult;
        this.server_time_offset = server_time_offset;
    }

    public KeyLookupResult(String _keyResult, String _errResult) {
        keyResult = _keyResult;
        errResult = _errResult;
    }

    public List<BigInteger> getNodeIndexes() {
        return nodeIndexes;
    }

    public GetOrSetNonceResult getNonceResult() {
        return nonceResult;
    }

    public String getKeyResult() {
        return keyResult;
    }

    public String getErrResult() {
        return errResult;
    }

    public BigInteger getServerTimeOffset() {
        return server_time_offset;
    }

}
