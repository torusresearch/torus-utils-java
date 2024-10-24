package org.torusresearch.torusutils;

import static org.torusresearch.fetchnodedetails.types.Utils.METADATA_MAP;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.analytics.SentryUtils;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCErrorInfo;
import org.torusresearch.torusutils.apis.requests.GetMetadataParams;
import org.torusresearch.torusutils.apis.responses.GetMetadataResponse;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierKey;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierLookupResponse;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;
import org.torusresearch.torusutils.helpers.Common;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.MetadataUtils;
import org.torusresearch.torusutils.helpers.NodeUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.TorusUtilsExtraParams;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.common.ImportedShare;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyLookupResult;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyResult;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TorusKeyType;
import org.torusresearch.torusutils.types.common.TorusOptions;
import org.torusresearch.torusutils.types.common.TorusPublicKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;

import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import io.reactivex.annotations.Nullable;

public class TorusUtils {
    private final String defaultHost;
    private final TorusOptions options;
    private int sessionTime = 86400;
    private final TorusKeyType keyType;
    private String apiKey = "torus-default";

    {
        setupBouncyCastle();
        SentryUtils.init();
    }

    public TorusUtils(TorusOptions options) throws TorusUtilError {
        this.options = options;
        this.keyType = options.keyType;
        if (options.legacyMetadataHost == null) {
            if (isLegacyNetorkRouteMap(options.network)) {
                this.defaultHost = METADATA_MAP.get(options.network);
            } else {
                if (options.network.name().equalsIgnoreCase("sapphire_mainnet")) {
                    this.defaultHost = "https://node-1.node.web3auth.io/metadata";
                } else if (options.network.name().equalsIgnoreCase("sapphire_devnet")) {
                    this.defaultHost = "https://node-1.dev-node.web3auth.io/metadata";
                } else {
                    throw TorusUtilError.INVALID_INPUT;
                }
            }
        } else {
            this.defaultHost = options.legacyMetadataHost;
        }
    }

    public static boolean isLegacyNetorkRouteMap(@NotNull Web3AuthNetwork network) {
        // TODO: Fix this in fetchnodedetails, comparison should be against .legacy(network)
        return !network.name().toLowerCase().contains("sapphire");
    }

    @SuppressWarnings("unused")
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
        APIUtils.setApiKey(apiKey);
    }

    @SuppressWarnings("unused")
    public void removeApiKey() {
        this.apiKey = "torus-default";
        APIUtils.setApiKey("torus-default");
    }

    public void setSessionTime(int sessionTime) {
        this.sessionTime = sessionTime;
    }

    private void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            // Web3j will set up the provider lazily when it's first used.
            return;
        }
        if (provider.getClass().equals(BouncyCastleProvider.class)) {
            // BC with same package name, shouldn't happen in real life.
            return;
        }
        // Android registers its own BC provider. As it might be outdated and might not include
        // all needed ciphers, we substitute it with a known BC bundled in the app.
        // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
        // of that it's possible to have another BC implementation loaded in VM.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @SuppressWarnings("unused")
    public static String getPostboxKey(TorusKey torusKey) {
        if (torusKey.getMetadata().getTypeOfUser() == TypeOfUser.v1) {
            return (torusKey.getFinalKeyData().getPrivKey() == null || torusKey.getFinalKeyData().getPrivKey().isEmpty()) ? torusKey.getoAuthKeyData().getPrivKey() : torusKey.getFinalKeyData().getPrivKey();
        }
        return torusKey.getoAuthKeyData().getPrivKey();
    }

    public TorusKey retrieveShares(@NotNull String[] endpoints, @NotNull String verifier, @NotNull VerifierParams verifierParams, @NotNull String idToken, @Nullable TorusUtilsExtraParams extraParams) throws Exception {
        TorusUtilsExtraParams params = (extraParams == null) ? new TorusUtilsExtraParams() : extraParams;
        if (params.session_token_exp_second == null) {
            params.session_token_exp_second = this.sessionTime;
        }

        return NodeUtils.retrieveOrImportShare(this.defaultHost, (options.serverTimeOffset == null) ? 0 : options.serverTimeOffset, this.options.enableOneKey, this.defaultHost, this.options.network, this.options.clientId, endpoints, verifier, verifierParams, idToken, null, this.apiKey, null, params);
    }

    public TorusPublicKey getPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo(), this.options.enableOneKey);
    }

    public TorusKey importPrivateKey(
            @NotNull String[] endpoints,
            @NotNull BigInteger[] nodeIndexes,
            @NotNull TorusNodePub[] nodePubKeys,
            @NotNull String verifier,
            @NotNull VerifierParams verifierParams,
            @NotNull String idToken,
            @NotNull String newPrivateKey,
            @Nullable TorusUtilsExtraParams extraParams
    ) throws Exception {
        TorusUtilsExtraParams params = (extraParams == null) ? new TorusUtilsExtraParams() : extraParams;
        if (params.session_token_exp_second == null) {
            params.session_token_exp_second = this.sessionTime;
        }

        if (endpoints.length != nodeIndexes.length) {
            throw TorusUtilError.RUNTIME_ERROR("Length of endpoints must be the same as length of nodeIndexes");
        }

        List<ImportedShare> shares = KeyUtils.generateShares(this.keyType, (options.serverTimeOffset == null) ? 0 : options.serverTimeOffset, Arrays.asList(nodeIndexes), Arrays.asList(nodePubKeys), newPrivateKey);

        return NodeUtils.retrieveOrImportShare(this.defaultHost, this.options.serverTimeOffset, this.options.enableOneKey, this.defaultHost, this.options.network, this.options.clientId, endpoints, verifier, verifierParams, idToken, shares.toArray(new ImportedShare[0]), this.apiKey, newPrivateKey, params);
    }

    public TorusPublicKey getUserTypeAndAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo(), true);
    }

    private TorusPublicKey getNewPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId, Web3AuthNetwork network, @NotNull Boolean enableOneKey) throws Exception {
        KeyLookupResult keyAssignResult = NodeUtils.getPubKeyOrKeyAssign(endpoints, network, verifier, verifierId, this.defaultHost, this.options.serverTimeOffset, extendedVerifierId);

        JsonRPCErrorInfo errorResult = keyAssignResult.errorResult;
        if (errorResult != null) {
            if (errorResult.message.toLowerCase().contains("verifier not supported")) {
                throw TorusUtilError.RUNTIME_ERROR("Verifier not supported. Check if you:\n1. Are on the right network (Torus testnet/mainnet)\n2. Have setup a verifier on dashboard.web3auth.io?");
            } else {
                throw TorusUtilError.RUNTIME_ERROR(errorResult.message);
            }
        }

        KeyResult keyResult = keyAssignResult.keyResult;
        if (keyResult == null || keyResult.keys.length == 0) {
            throw TorusUtilError.RUNTIME_ERROR("node results do not match at first lookup");
        }

        GetOrSetNonceResult nonceResult = keyAssignResult.nonceResult;
        if (nonceResult == null && extendedVerifierId == null && !isLegacyNetorkRouteMap(network)) {
            throw TorusUtilError.RUNTIME_ERROR("metadata nonce is missing in share response");
        }

        String pubKey = KeyUtils.getPublicKeyFromCoords(keyResult.keys[0].pub_key_X, keyResult.keys[0].pub_key_Y, false);

        PubNonce pubNonce = null;
        BigInteger nonce;
        if (nonceResult != null && nonceResult.nonce != null && !nonceResult.nonce.isEmpty()) {
            nonce = new BigInteger(nonceResult.nonce);
        } else {
            nonce = BigInteger.ZERO;
        }

        String oAuthPubKey;
        String finalPubKey;

        Integer finalServerTimeOffset = (this.options.serverTimeOffset != null) ? this.options.serverTimeOffset : keyAssignResult.server_time_offset;

        if (extendedVerifierId != null) {
            finalPubKey = pubKey;
            oAuthPubKey = finalPubKey;
        } else if (isLegacyNetorkRouteMap(network)) {
            ArrayList<LegacyVerifierKey> legacyKeys = new ArrayList<>();
            for (VerifierKey i : keyAssignResult.keyResult.keys) {
                legacyKeys.add(new LegacyVerifierKey(i.pub_key_X, i.pub_key_Y, i.address));
            }
            LegacyVerifierLookupResponse verifierLegacyLookupItem =
                    new LegacyVerifierLookupResponse(legacyKeys.toArray(new LegacyVerifierKey[0]), finalServerTimeOffset.toString());
            return formatLegacyPublicKeyData(verifierLegacyLookupItem, enableOneKey, keyAssignResult.keyResult.is_new_key, finalServerTimeOffset);
        } else {
            String[] pubKeyCoords = KeyUtils.getPublicKeyCoords(pubKey);
            String _X = pubKeyCoords[0];
            String _Y = pubKeyCoords[1];
            PubNonce finalPubNonce = null;
            if (nonceResult != null && nonceResult.pubNonce != null) {
                finalPubNonce = nonceResult.pubNonce;
            }
            oAuthPubKey = KeyUtils.getPublicKeyFromCoords(_X, _Y, true);
            finalPubKey = oAuthPubKey;
            pubNonce = finalPubNonce;
            if (pubNonce != null && !pubNonce.x.isEmpty() && !pubNonce.y.isEmpty()) {
                String pubNonceKey = KeyUtils.getPublicKeyFromCoords(pubNonce.x, pubNonce.y, true);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, pubNonceKey), false);

            } else {
                throw TorusUtilError.METADATA_NONCE_MISSING;
            }
        }

        if (oAuthPubKey == null || finalPubKey == null) {
            throw new Error("could not derive private key");
        }
        String[] oAuthPubKeyCoords = KeyUtils.getPublicKeyCoords(oAuthPubKey);
        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPubKey);

        String oAuthPubKeyX = oAuthPubKeyCoords[0];
        String oAuthPubKeyY = oAuthPubKeyCoords[1];
        String finalPubKeyX = finalPubKeyCoords[0];
        String finalPubKeyY = finalPubKeyCoords[1];

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(oAuthPubKeyX, oAuthPubKeyY);
        String finalAddresss = KeyUtils.generateAddressFromPubKey(finalPubKeyX, finalPubKeyY);

        return new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, oAuthPubKeyX, oAuthPubKeyY),
                new FinalPubKeyData(finalAddresss, finalPubKeyX, finalPubKeyY),
                new Metadata(pubNonce, nonce, TypeOfUser.v2, ((nonceResult != null) && (nonceResult.upgraded != null) && (nonceResult.upgraded)), finalServerTimeOffset),
                new NodesData(keyAssignResult.nodeIndexes));
    }

    private TorusPublicKey formatLegacyPublicKeyData(@NotNull LegacyVerifierLookupResponse finalKeyResult, boolean enableOneKey, boolean isNewKey,
                                                     @NotNull Integer serverTimeOffset) throws Exception {
        LegacyVerifierKey key = finalKeyResult.keys[0];
        String X = key.pub_key_X;
        String Y = key.pub_key_Y;
        GetOrSetNonceResult nonceResult = null;
        String finalPubKey;
        BigInteger nonce;
        TypeOfUser typeOfUser;
        PubNonce pubNonce = null;

        String oAuthPubKey = KeyUtils.getPublicKeyFromCoords(X, Y, true);
        Integer finalServerTimeOffset = (this.options.serverTimeOffset == null) ? serverTimeOffset : this.options.serverTimeOffset;

        if (enableOneKey) {
            nonceResult = MetadataUtils.getOrSetNonce(this.defaultHost, X, Y, finalServerTimeOffset, null, !isNewKey, null);
            nonce = (nonceResult.nonce == null) ? BigInteger.ZERO : new BigInteger(nonceResult.nonce, 16);
            typeOfUser = (nonceResult.typeOfUser == null) ? TypeOfUser.v1 : nonceResult.typeOfUser;

            if (typeOfUser == TypeOfUser.v1) {
                finalPubKey = oAuthPubKey;
                GetMetadataResponse metadataResponse = MetadataUtils.getMetadata(this.defaultHost, new GetMetadataParams(X, Y));
                nonce = new BigInteger(Common.isEmpty(metadataResponse.message) ? "0" : metadataResponse.message, 16);

                if (nonce.compareTo(BigInteger.ZERO) > 0) {
                    String noncePublicKey = KeyUtils.privateToPublic(nonce);
                    finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
                }
            } else if (typeOfUser == TypeOfUser.v2) {
                if (nonceResult.pubNonce == null) {
                    throw TorusUtilError.RUNTIME_ERROR("getOrSetNonce should always return typeOfUser.");
                }
                String pubNonceKey = KeyUtils.getPublicKeyFromCoords(nonceResult.pubNonce.x, nonceResult.pubNonce.y, true);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, pubNonceKey), false);
                pubNonce = nonceResult.pubNonce;
            } else {
                throw TorusUtilError.RUNTIME_ERROR("getOrSetNonce should always return typeOfUser.");
            }
        } else {
            typeOfUser = TypeOfUser.v1;
            finalPubKey = oAuthPubKey;
            GetMetadataResponse metadataResponse = MetadataUtils.getMetadata(this.defaultHost, new GetMetadataParams(X, Y));
            nonce = new BigInteger(Common.isEmpty(metadataResponse.message) ? "0" : metadataResponse.message, 16);
            if (nonce.compareTo(BigInteger.ZERO) > 0) {
                String noncePublicKey = KeyUtils.privateToPublic(nonce);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
            }
        }

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(Common.padLeft(X, '0', 64), Common.padLeft(Y, '0', 64));

        if (typeOfUser == TypeOfUser.v2 && finalPubKey == null) {
            throw TorusUtilError.PRIVATE_KEY_DERIVE_FAILED;
        }

        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPubKey);
        String finalAddress = KeyUtils.generateAddressFromPubKey(finalPubKeyCoords[0], finalPubKeyCoords[1]);

        return new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, Common.padLeft(X, '0', 64), Common.padLeft(Y, '0', 64)),
                new FinalPubKeyData(finalAddress, finalPubKeyCoords[0], finalPubKeyCoords[1]),
                new Metadata(pubNonce, nonce, typeOfUser, (nonceResult != null && nonceResult.upgraded != null) ? nonceResult.upgraded : false, serverTimeOffset),
                new NodesData(new ArrayList<>()));
    }

    private Web3AuthNetwork getNetworkInfo() {
        return this.options.network;
    }
}
