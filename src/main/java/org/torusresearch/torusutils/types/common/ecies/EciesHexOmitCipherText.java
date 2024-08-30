package org.torusresearch.torusutils.types.common.ecies;

import org.jetbrains.annotations.NotNull;

public class EciesHexOmitCipherText {
    public final String iv;
    public final String ephemPublicKey;
    public final String mac;
    public final String mode;

    public EciesHexOmitCipherText(@NotNull String iv, @NotNull String ephemPublicKey, @NotNull String mac, @NotNull String mode) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.mode = mode;
    }

    @SuppressWarnings("unused")
    public EciesHexOmitCipherText(@NotNull String iv, @NotNull String ephemPublicKey, @NotNull String mac) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.mode = "AES256";
    }
}
