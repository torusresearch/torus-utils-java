package org.torusresearch.torusutils.types.common.ecies;

import org.jetbrains.annotations.NotNull;

public class Ecies {

    private final String iv;
    private final String ephemPublicKey;
    private final String mac;
    private final String mode;
    private final String ciphertext;

    @SuppressWarnings("unused")
    public Ecies(@NotNull String iv, @NotNull String ephemPublicKey, @NotNull String ciphertext, @NotNull String mac, @NotNull String mode) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.ciphertext = ciphertext;
        this.mode = mode;
    }

    public Ecies(@NotNull String iv, @NotNull String ephemPublicKey, @NotNull String ciphertext, @NotNull String mac) {
        this.iv = iv;
        this.ephemPublicKey = ephemPublicKey;
        this.mac = mac;
        this.ciphertext = ciphertext;
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

    public String getCiphertext() {
        return ciphertext;
    }

    public EciesHexOmitCipherText omitCipherText() {
        return new EciesHexOmitCipherText(iv, ephemPublicKey, mac, mode);
    }


}
