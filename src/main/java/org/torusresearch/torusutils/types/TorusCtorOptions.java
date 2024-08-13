package org.torusresearch.torusutils.types;

import static org.torusresearch.fetchnodedetails.types.Utils.METADATA_MAP;
import static org.torusresearch.fetchnodedetails.types.Utils.SIGNER_MAP;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;

import java.math.BigInteger;

public class TorusCtorOptions {
    public final String legacyMetadataHost;
    // in seconds
    public final  Integer serverTimeOffset;
    public final Web3AuthNetwork network;
    public final String clientId;

    public final boolean enableOneKey = false;

    public final TorusKeyType keyType = TorusKeyType.secp256k1;

    public TorusCtorOptions(@NotNull String clientId, @NotNull Web3AuthNetwork network, @Nullable String legacyMetadataHost, @Nullable Integer serverTimeOffset, @NotNull Boolean enableOneKey) {
        this.clientId = clientId;
        this.network = network;
        if (legacyMetadataHost == null) {
            this.legacyMetadataHost = METADATA_MAP.get(network);
        } else {
            this.legacyMetadataHost = legacyMetadataHost;
        }
        if (serverTimeOffset != null ) {
            this.serverTimeOffset = serverTimeOffset;
        } else {
            this.serverTimeOffset = 0;
        }
    }
}
