package org.torusresearch.torusutils.types.common.ecies;

import org.jetbrains.annotations.NotNull;

public class EciesHexOmitCipherText {
    private final String iv;
    private final String ephemPublicKey;
    private final String mac;
    private final String mode;

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

    public String getIv() {
        return iv;
    }

    public String getEphemPublicKey() {
        return ephemPublicKey;
    }

    public String getMac() {
        return mac;
    }

    public String getMode() {
        return mode;
    }
}
