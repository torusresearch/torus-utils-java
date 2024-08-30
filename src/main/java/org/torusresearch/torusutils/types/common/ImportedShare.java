package org.torusresearch.torusutils.types.common;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.common.ecies.EciesHexOmitCipherText;

public class ImportedShare {

    public final String oauth_pub_key_x;
    public final String oauth_pub_key_y;
    public final Point final_user_point;
    public final String signing_pub_key_x;
    public final String signing_pub_key_y;
    public final String encryptedShare;
    public final EciesHexOmitCipherText encryptedShareMetadata;
    @Nullable
    public final String encryptedSeed;
    public final int node_index;
    @Nullable
    public final TorusKeyType key_type;
    public final String nonce_data;
    public final String nonce_signature;

    public ImportedShare(@NotNull String oauth_pub_key_x, @NotNull String oauth_pub_key_y, @NotNull Point final_user_point, @NotNull String signing_pub_key_x, @NotNull String signing_pub_key_y, @NotNull String encryptedShare,
                         @NotNull EciesHexOmitCipherText encryptedShareMetadata, @Nullable String encryptedSeed, int node_index, @Nullable TorusKeyType key_type,
                         @NotNull String nonce_data, @NotNull String nonce_signature) {
        this.oauth_pub_key_x = oauth_pub_key_x;
        this.oauth_pub_key_y = oauth_pub_key_y;
        this.final_user_point = final_user_point;
        this.signing_pub_key_x = signing_pub_key_x;
        this.signing_pub_key_y = signing_pub_key_y;
        this.encryptedShare = encryptedShare;
        this.encryptedShareMetadata = encryptedShareMetadata;
        this.encryptedSeed = encryptedSeed;
        this.node_index = node_index;
        this.key_type = key_type;
        this.nonce_data = nonce_data;
        this.nonce_signature = nonce_signature;
    }
}
