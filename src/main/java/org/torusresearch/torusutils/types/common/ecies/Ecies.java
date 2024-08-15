package org.torusresearch.torusutils.types.common.ecies;

import org.jetbrains.annotations.NotNull;

public class Ecies {

    public final String iv;
    public final String ephemPublicKey;
    public final String mac;
    public final String mode;
    public final String ciphertext;

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

    public EciesHexOmitCipherText omitCipherText() {
        return new EciesHexOmitCipherText(iv, ephemPublicKey, mac, mode);
    }


}
