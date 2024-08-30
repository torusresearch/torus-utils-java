package org.torusresearch.torusutils.types;


import org.jetbrains.annotations.Nullable;

public class VerifyParams {
    @Nullable
    public final String verifier_id;
    @Nullable
    public final String idtoken;

    public VerifyParams(@Nullable String verifier_id, @Nullable String idtoken) {
        this.verifier_id = verifier_id;
        this.idtoken = idtoken;
    }
}
