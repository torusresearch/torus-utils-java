package org.torusresearch.torusutils.apis;

public class VerifierLookupRequestResult {
    private final VerifierLookupItem[] keys;
    public VerifierLookupRequestResult(VerifierLookupItem[] _keys) {
        keys = _keys;
    }
    public VerifierLookupItem[] getKeys() {
        return keys;
    }
}
