package org.torusresearch.torusutils.types.common.ecies;

import org.jetbrains.annotations.NotNull;

public class Ecies extends EciesHexOmitCipherText {
    public final String ciphertext;

    @SuppressWarnings("unused")
    public Ecies(@NotNull String iv, @NotNull String ephemPublicKey, @NotNull String ciphertext, @NotNull String mac, @NotNull String mode) {
        super(iv, ephemPublicKey, mac, mode);
        this.ciphertext = ciphertext;
    }

    public Ecies(@NotNull String iv, @NotNull String ephemPublicKey, @NotNull String ciphertext, @NotNull String mac) {
        super(iv,ephemPublicKey,mac,"AES256");
        this.ciphertext = ciphertext;
    }

    public EciesHexOmitCipherText omitCipherText() {
        return new EciesHexOmitCipherText(iv, ephemPublicKey, mac, mode);
    }
}
