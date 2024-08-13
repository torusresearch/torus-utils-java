package org.torusresearch.torusutils.apis.responses;

import org.jetbrains.annotations.Nullable;
import org.torusresearch.torusutils.types.common.TypeOfUser;
import org.torusresearch.torusutils.types.common.PubNonce;

public class GetOrSetNonceResult {
    @Nullable
    public final TypeOfUser typeOfUser;
    @Nullable
    public String nonce; // This is not final as in one case the nonce needs to be removed.

    @Nullable
    public final PubNonce pubNonce;
    @Nullable
    public final String ipfs;
    @Nullable
    public final Boolean upgraded;

    public GetOrSetNonceResult(@Nullable TypeOfUser typeOfUser, @Nullable String nonce, @Nullable PubNonce pubNonce, @Nullable String ipfs, @Nullable Boolean upgraded) {
        this.typeOfUser = typeOfUser;
        this.nonce = nonce;
        this.pubNonce = pubNonce;
        this.ipfs = ipfs;
        this.upgraded = upgraded;
    }
}
