package org.torusresearch.torusutils.types;


import org.jetbrains.annotations.Nullable;

public class VerifyParam {
    @Nullable
    public final String verifier_id;
    @Nullable
    public final String extended_verifier_id;

    public VerifyParam(@Nullable String verifier_id, @Nullable String extended_verifier_id) {
        this.verifier_id = verifier_id;
        this.extended_verifier_id = extended_verifier_id;
    }
}
