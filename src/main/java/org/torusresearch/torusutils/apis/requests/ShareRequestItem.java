package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.apis.VerifyParams;
import org.torusresearch.torusutils.types.VerifyParam;
import org.torusresearch.torusutils.types.common.ecies.EciesHexOmitCipherText;
import org.torusresearch.torusutils.apis.responses.CommitmentRequestResult;
import org.torusresearch.torusutils.types.TorusKeyType;
import org.torusresearch.torusutils.types.TorusUtilsExtraParams;

public class ShareRequestItem {
    public final String verifieridentifier;
    @Nullable
    public final String verifier_id;
    @Nullable
    public final String extended_verifier_id;
    public final String idtoken;
    @Nullable
    public final CommitmentRequestResult[] nodesignatures;
    @Nullable
    public final String pub_key_x;
    @Nullable
    public final String pub_key_y;
    @Nullable
    public final String signing_pub_key_x;
    @Nullable
    public final String signing_pub_key_y;
    @Nullable
    public final String encrypted_share;
    @Nullable
    public final EciesHexOmitCipherText encrypted_share_metadata;
    @Nullable
    public final int node_index;
    @Nullable
    public final TorusKeyType key_type;
    @Nullable
    public final String nonce_data;
    @Nullable
    public final String nonce_signature;
    @Nullable
    public final String[] sub_verifier_ids;
    public Integer session_token_exp_second = 86400;
    @Nullable
    public final VerifyParam[] verify_params;
    @Nullable
    public final String sss_endpoint;
    @Nullable
    public final String nonce;
    @Nullable
    public final String message;
    @Nullable
    public final String signature;
    @Nullable
    public final String clientDataJson;
    @Nullable
    public final String authenticatorData;
    @Nullable
    public final String publicKey;
    @Nullable
    public final String challenge;
    @Nullable
    public final String rpOrigin;
    @Nullable
    public final String rpId;
    @Nullable
    public final Integer timestamp;

    public ShareRequestItem(@NotNull String verifieridentifier, @Nullable String verifier_id, @Nullable String extended_verifier_id, @NotNull String idtoken, @NotNull TorusUtilsExtraParams extraParams, @Nullable CommitmentRequestResult[] nodesignatures, @Nullable String pub_key_x,
                            @Nullable String pub_key_y, @Nullable String signing_pub_key_x, @Nullable String signing_pub_key_y, @Nullable String encrypted_share, @Nullable EciesHexOmitCipherText encrypted_share_metadata, @Nullable Integer node_index,
                            @Nullable TorusKeyType key_type, @Nullable String nonce_data, @Nullable String nonce_signature, @Nullable String[] sub_verifier_ids, @Nullable VerifyParam[] verifyParams, @Nullable String sss_endpoint ) {
        this.verifieridentifier = verifieridentifier;
        this.verifier_id = verifier_id;
        this.extended_verifier_id = extended_verifier_id;
        this.idtoken = idtoken;
        this.nodesignatures = nodesignatures;
        this.pub_key_x = pub_key_x;
        this.pub_key_y = pub_key_y;
        this.signing_pub_key_x = signing_pub_key_x;
        this.signing_pub_key_y = signing_pub_key_y;
        this.encrypted_share = encrypted_share;
        this.encrypted_share_metadata = encrypted_share_metadata;
        this.node_index = node_index;
        this.key_type = key_type;
        this.nonce_data = nonce_data;
        this.nonce_signature = nonce_signature;
        this.sub_verifier_ids = sub_verifier_ids;
        if (extraParams.session_token_exp_second == null) {
            this.session_token_exp_second = extraParams.session_token_exp_second;
        }
        this.verify_params = verifyParams;
        this.sss_endpoint = sss_endpoint;

        this.nonce = extraParams.nonce;
        this.message = extraParams.message;
        this.signature = extraParams.signature;
        this.clientDataJson = extraParams.clientDataJson;
        this.authenticatorData = extraParams.authenticatorData;
        this.publicKey = extraParams.publicKey;
        this.challenge = extraParams.challenge;
        this.rpOrigin = extraParams.rpOrigin;
        this.rpId = extraParams.rpId;
        this.timestamp = extraParams.timestamp;
    }
}
