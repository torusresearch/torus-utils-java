package org.torusresearch.torusutils.apis;

public class KeyLookupResult {
    private final String keyResult;
    private final String errResult;

    public String getKeyResult() {
        return keyResult;
    }

    public String getErrResult() {
        return errResult;
    }

    public KeyLookupResult(String _keyResult, String _errResult) {
        keyResult = _keyResult;
        errResult = _errResult;
    }

}
