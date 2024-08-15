package org.torusresearch.torusutils.types.common.KeyLookup;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;

public class KeyResult {
    public VerifierKey[] keys;
    public final Boolean is_new_key;

    @SuppressWarnings("unused")
    public KeyResult(@NotNull VerifierKey[] keys, @NotNull Boolean is_new_key) {
        this.keys = keys;
        this.is_new_key = is_new_key;
    }

    public KeyResult(@NotNull Boolean is_new_key) {
        this.keys = new VerifierKey[]{};
        this.is_new_key = is_new_key;
    }
}
