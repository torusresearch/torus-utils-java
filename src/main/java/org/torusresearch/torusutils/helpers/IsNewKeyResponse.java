package org.torusresearch.torusutils.helpers;

import org.jetbrains.annotations.NotNull;

public class IsNewKeyResponse {

    public boolean isNewKey;
    public String publicKeyX;

    public IsNewKeyResponse(@NotNull boolean isNewKey, @NotNull String publicKeyX) {
        this.isNewKey = isNewKey;
        this.publicKeyX = publicKeyX;
    }
}
