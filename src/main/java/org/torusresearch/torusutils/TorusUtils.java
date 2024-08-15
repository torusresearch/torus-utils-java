package org.torusresearch.torusutils;

import static org.torusresearch.fetchnodedetails.types.Utils.METADATA_MAP;
import static org.torusresearch.torusutils.helpers.KeyUtils.getOrderOfCurve;
import static org.torusresearch.torusutils.helpers.Utils.calculateMedian;
import static org.torusresearch.torusutils.helpers.Utils.getOrSetNonce;
import static org.torusresearch.torusutils.helpers.Utils.getOrSetSapphireMetadataNonce;
import static org.torusresearch.torusutils.helpers.Utils.isLegacyNetorkRouteMap;
import static org.torusresearch.torusutils.helpers.Utils.kCombinations;
import static org.torusresearch.torusutils.helpers.Utils.thresholdSame;

import com.google.gson.Gson;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCErrorInfo;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.PubKey;
import org.torusresearch.torusutils.apis.requests.CommitmentRequestParams;
import org.torusresearch.torusutils.apis.requests.GetMetadataParams;
import org.torusresearch.torusutils.apis.requests.ShareRequestItem;
import org.torusresearch.torusutils.apis.requests.ShareRequestParams;
import org.torusresearch.torusutils.apis.responses.CommitmentRequestResult;
import org.torusresearch.torusutils.apis.responses.GetMetadataResponse;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.KeyAssignment;
import org.torusresearch.torusutils.apis.responses.ShareRequestResult;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierKey;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierLookupResponse;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.Lagrange;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.helpers.Utils;
import org.torusresearch.torusutils.helpers.encryption.Encryption;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.TorusUtilsExtraParams;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.common.ImportedShare;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyLookupResult;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyResult;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.SessionToken;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TorusKeyType;
import org.torusresearch.torusutils.types.common.TorusOptions;
import org.torusresearch.torusutils.types.common.TorusPublicKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;
import org.web3j.crypto.Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import io.reactivex.annotations.Nullable;
import okhttp3.internal.http2.Header;

public class TorusUtils {

    private final String defaultHost;
    private final TorusOptions options;
    private int sessionTime = 86400;
    private final TorusKeyType keyType;

    private String apiKey = "torus-default";

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public void removeApiKey() {
        this.apiKey = "torus-default";
    }

    public static final BigInteger secp256k1N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    {
        setupBouncyCastle();
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
                    throw TorusUtilError.CONFIGURATION_ERROR;
                }
            }
        } else {
            this.defaultHost = options.legacyMetadataHost;
        }
    }

    public static void setAPIKey(String apiKey) {
        APIUtils.setApiKey(apiKey);
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

    public static String getPostboxKey(TorusKey torusKey) {
        if (torusKey.getMetadata().getTypeOfUser() == TypeOfUser.v1) {
            return (torusKey.getFinalKeyData().getPrivKey() == null || torusKey.getFinalKeyData().getPrivKey().isEmpty()) ? torusKey.getoAuthKeyData().getPrivKey() : torusKey.getFinalKeyData().getPrivKey();
        }
        return torusKey.getoAuthKeyData().getPrivKey();
    }

    public static TorusKey retrieveOrImportShare(@NotNull String legacyMetadataHost, @Nullable Integer serverTimeOffset,
                                                 @NotNull Boolean enableOneKey, @NotNull String allowHost, @NotNull Web3AuthNetwork network,
                                                 @NotNull String clientId, @NotNull String[] endpoints, @NotNull String verifier, @NotNull VerifierParams verifierParams,
                                                 @NotNull String idToken, @Nullable ImportedShare[] importedShares, @NotNull String apiKey, @NotNull TorusUtilsExtraParams extraParams
    ) throws Exception {
        int threshold = (endpoints.length / 2) + 1;

        APIUtils.get(allowHost, new Header[]{new Header("x-api-key", apiKey), new Header("Origin", verifier), new Header("verifier", verifier), new Header("verifierid", verifierParams.verifier_id), new Header("network", network.name().toLowerCase()),
                new Header("clientid", clientId), new Header("enablegating", "true")}, true).get();

        KeyPair sessionAuthKey = KeyUtils.generateKeyPair();
        String sessionAuthKeySerialized = Utils.padLeft(Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())),'0', 64);
        String pubKey = Hex.toHexString(KeyUtils.serializePublicKey(sessionAuthKey.getPublic(), false));
        String[] pubKeyCoords = KeyUtils.getPublicKeyCoords(pubKey);
        String pubKeyX = pubKeyCoords[0];
        String pubKeyY = pubKeyCoords[1];
        String tokenCommitment = Hash.sha3String(idToken);

        boolean isImportShareReq = false;
        int importedShareCount = 0;

        if (importedShares != null && importedShares.length > 0) {
            if (importedShares.length != endpoints.length) {
                throw new Error("Invalid imported shares length");
            }
            isImportShareReq = true;
            importedShareCount = importedShares.length;
        }

        int minRequiredCommitmments = (endpoints.length * 3 / 4) + 1;


        List<CompletableFuture<String>> CommitmentRequests = new ArrayList<>();

        // make commitment requests to endpoints
        for (int i = 0; i < endpoints.length; i++) {
            CompletableFuture<String> commitmentRequest = APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("CommitmentRequest", new CommitmentRequestParams("mug00", tokenCommitment.replace("0x", ""), pubKeyX, pubKeyY, String.valueOf(System.currentTimeMillis()), verifier)), false);
            CommitmentRequests.add(i, commitmentRequest);
        }

        List<CommitmentRequestResult> nodeSigs = new ArrayList<>();
        int received = 0; // might need to be atomic

        Gson json = new Gson();
        for (CompletableFuture<String> commitment : CommitmentRequests) {
            String result = commitment.get();
            @SuppressWarnings({"unchecked"}) // Due to Type Erasure of Generic Types at Runtime. Java does this to ensure code is compatible with pre-generic versions of Java.
            JsonRPCResponse<CommitmentRequestResult> response = json.fromJson(result, JsonRPCResponse.class);
            if (response != null && response.getError() == null) {
                nodeSigs.add(response.getTypedResult(CommitmentRequestResult.class));
                received++;
                if (!isImportShareReq) {
                    if (received >= minRequiredCommitmments) {
                        break;
                    }
                }
            } else {
                if (isImportShareReq) {
                    // cannot continue. all must pass for import
                    break;
                }
            }
        }

        if (importedShareCount > 0 && (nodeSigs.size() != endpoints.length)) {
            throw TorusUtilError.COMMITMENT_REQUEST_FAILED;
        }

        GetOrSetNonceResult thresholdNonceData = null;
        boolean shareImportSuccess = false;

        List<ShareRequestResult> shareResponses = new ArrayList<>();
        PubKey thresholdPublicKey = null;

        String clientTime = String.valueOf((serverTimeOffset == null) ? 0 : serverTimeOffset) + (System.currentTimeMillis() / 1000L);

        if (isImportShareReq) {
            ArrayList<ShareRequestItem> importedItems = new ArrayList<>();
            for (int j = 0; j < endpoints.length; j++) {
                ImportedShare importShare = importedShares[j];

                ShareRequestItem shareRequestItem = new ShareRequestItem(verifier, verifierParams.verifier_id, verifierParams.extended_verifier_id,
                        idToken, extraParams, nodeSigs.toArray(new CommitmentRequestResult[0]), importShare.oauth_pub_key_x, importShare.oauth_pub_key_y,
                        importShare.signing_pub_key_x, importShare.signing_pub_key_y, importShare.encryptedShare,
                        importShare.encryptedShareMetadata, importShare.node_index, importShare.key_type,
                        importShare.nonce_data, importShare.nonce_signature, verifierParams.sub_verifier_ids, verifierParams.verify_params, endpoints[j]
                );
                importedItems.add(shareRequestItem);
            }
            String req = APIUtils.generateJsonRPCObject("ImportShares", new ShareRequestParams(importedItems.toArray(new ShareRequestItem[0]), clientTime));
            String result = APIUtils.post(endpoints[Utils.getProxyCoordinatorEndpointIndex(endpoints, verifier, verifierParams.verifier_id)], req, true).get();
            @SuppressWarnings({"unchecked"}) // Due to Type Erasure of Generic Types at Runtime. Java does this to ensure code is compatible with pre-generic versions of Java.
            JsonRPCResponse<ShareRequestResult[]> response = json.fromJson(result, JsonRPCResponse.class);
            if (response != null && response.getError() == null) {
                shareImportSuccess = true;
            }

            if (isImportShareReq && !shareImportSuccess) {
                throw TorusUtilError.IMPORT_SHARE_FAILED;
            }

            ShareRequestResult[] shares = response.getTypedResult(ShareRequestResult[].class);
            shareResponses.addAll(Arrays.asList(shares));
            List<PubKey> pubkeys = Arrays.stream(shares).filter(item -> item.keys.length > 0).map(item -> item.keys[0].public_key).collect(Collectors.toList());
            thresholdPublicKey = Utils.thresholdSame(pubkeys.toArray(new PubKey[0]), threshold);
        } else {
            ArrayList<CompletableFuture<String>> shareRequests = new ArrayList<>();
            for (String endpoint : endpoints) {
                ShareRequestItem shareRequestItem = new ShareRequestItem(verifier, verifierParams.verifier_id, verifierParams.extended_verifier_id,
                        idToken, extraParams, nodeSigs.toArray(new CommitmentRequestResult[0]), null, null,
                        null, null, null,
                        null, null, null,
                        null, null, verifierParams.sub_verifier_ids, verifierParams.verify_params, null);

                List<ShareRequestItem> shareRequestItems = new ArrayList<>();
                shareRequestItems.add(shareRequestItem);
                String req = APIUtils.generateJsonRPCObject("GetShareOrKeyAssign", new ShareRequestParams(shareRequestItems.toArray(new ShareRequestItem[0]), clientTime));
                shareRequests.add(APIUtils.post(endpoint, req, true));
            }

            for (CompletableFuture<String> item : shareRequests) {
                @SuppressWarnings({"unchecked"}) // Due to Type Erasure of Generic Types at Runtime. Java does this to ensure code is compatible with pre-generic versions of Java.
                JsonRPCResponse<ShareRequestResult> response = json.fromJson(item.get(), JsonRPCResponse.class);

                if (response != null && response.getError() == null) {
                    shareResponses.add(response.getTypedResult(ShareRequestResult.class));
                }

                List<PubKey> pubkeys = shareResponses.stream().filter(res -> res.keys.length > 0).map(res -> res.keys[0].public_key).collect(Collectors.toList());
                thresholdPublicKey = Utils.thresholdSame(pubkeys.toArray(new PubKey[0]), threshold);

                if (thresholdPublicKey != null) {
                    break;
                }
            }
        }

        if (thresholdPublicKey == null) {
            throw TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
        }

        ArrayList<String> serverTimeOffsets = new ArrayList<>();

        for (ShareRequestResult item : shareResponses) {
            if (thresholdNonceData == null && verifierParams.extended_verifier_id == null) {
                String currentPubKeyX = Utils.padLeft(item.keys[0].public_key.getX(), '0', 64);
                String thresholdPubKeyX = Utils.padLeft(thresholdPublicKey.getX(), '0', 64);
                if (item.keys[0].nonce_data != null) {
                    GetOrSetNonceResult pubnonce = item.keys[0].nonce_data;
                    if (pubnonce != null && currentPubKeyX.equalsIgnoreCase(thresholdPubKeyX)) {
                        thresholdNonceData = pubnonce;
                    }
                }
            }

            serverTimeOffsets.add((item.server_time_offset != null && !item.server_time_offset.isEmpty()) ? item.server_time_offset : "0");
        }

        List<Integer> serverOffsetTimes = serverTimeOffsets.stream().map(Integer::parseInt).collect(Collectors.toList());
        Integer serverOffsetResponse = (serverTimeOffset != null) ? serverTimeOffset : calculateMedian(serverOffsetTimes);

        if (thresholdNonceData == null && verifierParams.extended_verifier_id == null && !isLegacyNetorkRouteMap(network)) {
            GetOrSetNonceResult metadataNonce = getOrSetSapphireMetadataNonce(legacyMetadataHost, network, thresholdPublicKey.getX(), thresholdPublicKey.getY(), serverOffsetResponse, null, false, null);
            thresholdNonceData = metadataNonce;
        }

        int thresholdReqCount = (importedShares != null && importedShares.length > 0) ? endpoints.length : threshold;

        if (!(shareResponses.size() >= thresholdReqCount && thresholdPublicKey != null && (thresholdNonceData != null || verifierParams.extended_verifier_id != null || isLegacyNetorkRouteMap(network)))) {
            throw TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
        }

        ArrayList<String> shares = new ArrayList<>();
        ArrayList<String> sessionTokenSigs = new ArrayList<>();
        ArrayList<String> sessionTokens = new ArrayList<>();
        ArrayList<Integer> nodeIndexes = new ArrayList<>();
        ArrayList<SessionToken> sessionTokenDatas = new ArrayList<>();
        ArrayList<String> isNewKeys = new ArrayList<>();

        for (ShareRequestResult item : shareResponses) {
            isNewKeys.add(item.is_new_key.toString());

            if (item.session_token_sigs.length > 0) {
                if (item.session_token_sig_metadata != null && item.session_token_sig_metadata.length > 0) {
                    String decrypted = Encryption.decryptNodeData(item.session_token_sig_metadata[0], item.session_token_sigs[0], sessionAuthKeySerialized);
                    sessionTokenSigs.add(decrypted);
                } else {
                    sessionTokenSigs.add(item.session_token_sigs[0]);
                }
            }

            if (item.session_tokens.length > 0) {
                if (item.session_token_metadata != null && item.session_token_metadata.length > 0) {
                    String decrypted = Encryption.decryptNodeData(item.session_token_metadata[0], item.session_tokens[0], sessionAuthKeySerialized);
                    sessionTokens.add(decrypted);
                } else {
                    sessionTokens.add(item.session_tokens[0]);
                }
            }

            if (item.keys.length > 0) {
                KeyAssignment latestKey = item.keys[0];
                nodeIndexes.add(latestKey.node_index);
                String decoded = new String(Base64.getDecoder().decode(latestKey.share.getBytes(StandardCharsets.UTF_8)));
                String decryped = Encryption.decryptNodeData(latestKey.share_metadata, decoded, sessionAuthKeySerialized);
                shares.add(decryped);
            }
        }

        if (verifierParams.extended_verifier_id == null && sessionTokenSigs.size() < threshold) {
            throw TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
        }

        if (verifierParams.extended_verifier_id == null && sessionTokens.size() < threshold) {
            throw new RuntimeException("Insufficient number of signatures from nodes");
        }

        for (int i = 0; i < sessionTokens.size(); i++) {
            String token = sessionTokens.get(i);
            if (token != null) {
                // decode token, can be either hex or base64
                try {
                    byte[] tokenBytes = null;
                    tokenBytes = Hex.decode(token);
                    String tokenBase64 = Base64.getEncoder().encodeToString(tokenBytes);
                    sessionTokenDatas.add(new SessionToken(tokenBase64, sessionTokenSigs.get(i), shareResponses.get(i).node_pubx, shareResponses.get(i).node_puby));
                } catch (Exception e) {
                    sessionTokenDatas.add(new SessionToken(token, sessionTokenSigs.get(i), shareResponses.get(i).node_pubx, shareResponses.get(i).node_puby));
                }
            }
        }

        Map<Integer, String> decryptedShares = new HashMap<>();
        for (int i = 0; i < shares.size(); i++) {
            if (shares.get(i) != null) {
                decryptedShares.put(nodeIndexes.get(i), shares.get(i));
            }
        }

        List<Integer> elements = new ArrayList<>();
        for (int i = 0; i <= Collections.max(decryptedShares.keySet()); i++) {
            elements.add(i);
        }

        List<List<Integer>> allCombis = kCombinations(elements, threshold);

        BigInteger privateKey = null;
        for (int j = 0; j < allCombis.size(); j++) {
            List<Integer> currentCombi = allCombis.get(j);
            Map<Integer, String> currentCombiShares = decryptedShares.entrySet().stream().filter(entry -> currentCombi.contains(entry.getKey())).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            List<BigInteger> combiShares = new ArrayList<>(currentCombiShares.values()).stream().map(cs -> new BigInteger(cs, 16)).collect(Collectors.toList());
            List<BigInteger> combiIndices = new ArrayList<>(currentCombiShares.keySet()).stream().map(is -> new BigInteger(String.valueOf(is))).collect(Collectors.toList());
            BigInteger derivedPrivateKey = Lagrange.lagrangeInterpolation(combiShares.toArray(new BigInteger[0]), combiIndices.toArray(new BigInteger[0]));
            if (derivedPrivateKey == null) {
                continue;
            }
            String decryptedPublicKey = KeyUtils.privateToPublic(derivedPrivateKey);
            String[] derivedPublicKeyCoords = KeyUtils.getPublicKeyCoords(decryptedPublicKey);
            String thresholdPubKeyX = Utils.padLeft(thresholdPublicKey.getX(), '0', 64);
            String thresholdPubKeyY = Utils.padLeft(thresholdPublicKey.getY(), '0', 64);
            if (derivedPublicKeyCoords[0].equalsIgnoreCase(thresholdPubKeyX) && derivedPublicKeyCoords[1].equalsIgnoreCase(thresholdPubKeyY)) {
                privateKey = derivedPrivateKey;
                break;
            }
        }

        if (privateKey == null) {
            throw TorusUtilError.PRIVATE_KEY_DERIVE_FAILED;
        }

        String thesholdIsNewKey = thresholdSame(isNewKeys.toArray(new String[0]), threshold);

        String oAuthKey = Utils.padLeft(privateKey.toString(16), '0', 64);
        String oAuthPublicKey = KeyUtils.privateToPublic(privateKey);
        String[] oAuthPublicKeyCoords = KeyUtils.getPublicKeyCoords(oAuthPublicKey);
        BigInteger metadataNonce = (thresholdNonceData != null && thresholdNonceData.nonce != null) ? new BigInteger(Utils.padLeft(thresholdNonceData.nonce, '0', 64), 16) : BigInteger.ZERO;
        String finalPublicKey = null;
        PubNonce pubNonce = null;
        TypeOfUser typeOfUser = TypeOfUser.v1;

        if (verifierParams.extended_verifier_id != null) {
            typeOfUser = TypeOfUser.v2;
            finalPublicKey = oAuthPublicKey;
        } else if (isLegacyNetorkRouteMap(network)) {
            if (enableOneKey) {
                Boolean isNewKey = (!(thesholdIsNewKey != null && thesholdIsNewKey.equalsIgnoreCase("true")));
                GetOrSetNonceResult nonce = getOrSetNonce(legacyMetadataHost, thresholdPublicKey.getX(), thresholdPublicKey.getY(), serverOffsetResponse, oAuthKey, isNewKey, null);
                metadataNonce = (nonce.nonce != null) ? new BigInteger(Utils.padLeft(nonce.nonce, '0', 64), 16) : BigInteger.ZERO;
                typeOfUser = (nonce.typeOfUser != null) ? nonce.typeOfUser : TypeOfUser.v1;

                if (typeOfUser == TypeOfUser.v2) {
                    pubNonce = nonce.pubNonce;
                    if (pubNonce != null && !pubNonce.x.isEmpty() && !pubNonce.y.isEmpty()) {
                        String pubNonceKey = KeyUtils.getPublicKeyFromCoords(pubNonce.x, pubNonce.y, true);
                        finalPublicKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPublicKey, pubNonceKey), false);
                    } else {
                        throw new RuntimeException("Public nonce is missing");
                    }
                } else {
                    typeOfUser = TypeOfUser.v1;
                    metadataNonce = new BigInteger(Utils.padLeft(getMetadata(legacyMetadataHost, new GetMetadataParams(oAuthPublicKeyCoords[0], oAuthPublicKeyCoords[1])).message, '0', 64), 16);
                    BigInteger privateKeyWithNonce = new BigInteger(Utils.padLeft(oAuthKey, '0', 64), 16).add(metadataNonce);
                    finalPublicKey = KeyUtils.privateToPublic(privateKeyWithNonce);
                }
            } else {
                typeOfUser = TypeOfUser.v1;
                metadataNonce = new BigInteger(Utils.padLeft(getMetadata(legacyMetadataHost, new GetMetadataParams(oAuthPublicKeyCoords[0], oAuthPublicKeyCoords[1])).message, '0', 64), 16);
                BigInteger privateKeyWithNonce = new BigInteger(Utils.padLeft(oAuthKey, '0', 64), 16).add(metadataNonce);
                finalPublicKey = KeyUtils.privateToPublic(privateKeyWithNonce);
            }
        } else {
            typeOfUser = TypeOfUser.v2;
            finalPublicKey = oAuthPublicKey;
            if (thresholdNonceData != null && thresholdNonceData.pubNonce != null && (!(thresholdNonceData.pubNonce.x.isEmpty() || thresholdNonceData.pubNonce.y.isEmpty()))) {
                PubNonce pubNonceObject = thresholdNonceData.pubNonce;
                String pubNonceKey = KeyUtils.getPublicKeyFromCoords(pubNonceObject.x, pubNonceObject.y, true);
                finalPublicKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPublicKey, pubNonceKey), false);
                pubNonce = pubNonceObject;
            } else {
                throw TorusUtilError.METADATA_NONCE_MISSING; // TODO: Fix this
            }
        }

        if (finalPublicKey == null) {
            throw TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
        }

        String oAuthKeyAddress = KeyUtils.generateAddressFromPubKey(oAuthPublicKeyCoords[0], oAuthPublicKeyCoords[1]);
        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPublicKey);

        String finalEvmAddress = KeyUtils.generateAddressFromPubKey(finalPubKeyCoords[0], finalPubKeyCoords[1]);

        String finalPrivKey = "";

        if (typeOfUser == TypeOfUser.v1 || (typeOfUser == TypeOfUser.v2 && metadataNonce.compareTo(BigInteger.ZERO) > 0)) {
            BigInteger privateKeyWithNonce = privateKey.add(metadataNonce).mod(getOrderOfCurve());
            finalPrivKey = Utils.padLeft(privateKeyWithNonce.toString(16), '0', 64);

        }
        // TODO: Should actually just pass the new private key for this function, if it is not null, it can then be checked against the final private key if it has been imported, as an added safety check for import.

        Boolean isUpgraded = null;

        if (typeOfUser == TypeOfUser.v2) {
            isUpgraded = metadataNonce.equals(BigInteger.ZERO);
        }

        return new TorusKey(
                new FinalKeyData(finalEvmAddress, finalPubKeyCoords[0], finalPubKeyCoords[1], finalPrivKey),
                new OAuthKeyData(oAuthKeyAddress, oAuthPublicKeyCoords[0], oAuthPublicKeyCoords[1], oAuthKey),
                new SessionData(sessionTokenDatas, sessionAuthKeySerialized),
                new Metadata(pubNonce, metadataNonce, typeOfUser, isUpgraded, serverOffsetResponse),
                new NodesData(nodeIndexes));
    }

    public static GetMetadataResponse getMetadata(String legacyMetadataHost, GetMetadataParams data) throws ExecutionException, InterruptedException {
        Gson gson = new Gson();
        String metadata = gson.toJson(data, GetMetadataParams.class);
        String metadataApiResponse = APIUtils.post(legacyMetadataHost + "/get", metadata, true).get();
        return gson.fromJson(metadataApiResponse, GetMetadataResponse.class);
    }

    public TorusPublicKey getNewPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId, Web3AuthNetwork network, @NotNull Boolean enableOneKey) throws Exception {
        KeyLookupResult keyAssignResult = Utils.getPubKeyOrKeyAssign(endpoints, network, verifier, verifierId, this.defaultHost, this.options.serverTimeOffset, extendedVerifierId);

        JsonRPCErrorInfo errorResult = keyAssignResult.errorResult;
        if (errorResult != null) {
            if (errorResult.message.toLowerCase().contains("verifier not supported")) {
                throw new RuntimeException("Verifier not supported. Check if you:\n1. Are on the right network (Torus testnet/mainnet)\n2. Have setup a verifier on dashboard.web3auth.io?");
            } else {
                throw new RuntimeException(errorResult.message);
            }
        }

        KeyResult keyResult = keyAssignResult.keyResult;
        if (keyResult == null || keyResult.keys.length == 0) {
            throw new RuntimeException("node results do not match at first lookup " + keyResult + ", " + errorResult);
        }

        GetOrSetNonceResult nonceResult = keyAssignResult.nonceResult;
        if (nonceResult == null && extendedVerifierId == null && !isLegacyNetorkRouteMap(network)) {
            throw new RuntimeException("metadata nonce is missing in share response");
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
                throw new RuntimeException("Public nonce is missing");
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
                new Metadata(pubNonce, nonce, TypeOfUser.v2, nonceResult != null && nonceResult.upgraded, finalServerTimeOffset),
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
            nonceResult = Utils.getOrSetNonce(this.defaultHost, X, Y, finalServerTimeOffset, null, !isNewKey, null);
            nonce = (nonceResult.nonce == null) ? BigInteger.ZERO : new BigInteger(nonceResult.nonce, 16);
            typeOfUser = (nonceResult.typeOfUser == null) ? TypeOfUser.v1 : nonceResult.typeOfUser;

            if (typeOfUser == TypeOfUser.v1) {
                finalPubKey = oAuthPubKey;
                GetMetadataResponse metadataResponse = getMetadata(this.defaultHost, new GetMetadataParams(X, Y));
                nonce = new BigInteger(Utils.isEmpty(metadataResponse.message) ? "0" : metadataResponse.message, 16);

                if (nonce.compareTo(BigInteger.ZERO) > 0) {
                    String noncePublicKey = KeyUtils.privateToPublic(nonce);
                    finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
                }
            } else if (typeOfUser == TypeOfUser.v2) {
                if (nonceResult.pubNonce == null) {
                    throw new RuntimeException("getOrSetNonce should always return typeOfUser.");
                }
                String pubNonceKey = KeyUtils.getPublicKeyFromCoords(nonceResult.pubNonce.x, nonceResult.pubNonce.y, true);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, pubNonceKey), false);
                pubNonce = nonceResult.pubNonce;
            } else {
                throw new RuntimeException("getOrSetNonce should always return typeOfUser.");
            }
        } else {
            typeOfUser = TypeOfUser.v1;
            finalPubKey = oAuthPubKey;
            GetMetadataResponse metadataResponse = getMetadata(this.defaultHost, new GetMetadataParams(X, Y));
            nonce = new BigInteger(Utils.isEmpty(metadataResponse.message) ? "0" : metadataResponse.message, 16);
            if (nonce.compareTo(BigInteger.ZERO) > 0) {
                String noncePublicKey = KeyUtils.privateToPublic(nonce);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
            }
        }

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(Utils.padLeft(X, '0', 64), Utils.padLeft(Y, '0', 64));

        if (typeOfUser == TypeOfUser.v2 && finalPubKey == null) {
            throw TorusUtilError.PRIVATE_KEY_DERIVE_FAILED;
        }

        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPubKey);
        String finalAddress = KeyUtils.generateAddressFromPubKey(finalPubKeyCoords[0], finalPubKeyCoords[1]);

        return new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, Utils.padLeft(X, '0', 64), Utils.padLeft(Y, '0', 64)),
                new FinalPubKeyData(finalAddress, finalPubKeyCoords[0], finalPubKeyCoords[1]),
                new Metadata(pubNonce, nonce, typeOfUser, (nonceResult != null && nonceResult.upgraded != null) ? nonceResult.upgraded : false, serverTimeOffset),
                new NodesData(new ArrayList<>()));
    }

    public TorusPublicKey getPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo(), this.options.enableOneKey);
    }

    private String getMigratedNetworkInfo() {
        return this.options.network.toString();
    }

    private Web3AuthNetwork getNetworkInfo() {
        return this.options.network;
    }

    public TorusPublicKey getUserTypeAndAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo(), true);
    }

    public TorusKey retrieveShares(@NotNull String[] endpoints, @NotNull String verifier, @NotNull VerifierParams verifierParams, @NotNull String idToken, @Nullable TorusUtilsExtraParams extraParams) throws Exception {
        TorusUtilsExtraParams params = (extraParams == null) ? new TorusUtilsExtraParams() : extraParams;
        if (params.session_token_exp_second == null) {
            params.session_token_exp_second = this.sessionTime;
        }

        return TorusUtils.retrieveOrImportShare(this.defaultHost, (options.serverTimeOffset == null) ? 0 : options.serverTimeOffset, this.options.enableOneKey, this.defaultHost, this.options.network, this.options.clientId, endpoints, verifier, verifierParams, idToken, null, this.apiKey, params);
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
            throw new RuntimeException("Length of endpoints must be the same as length of nodeIndexes");
        }

        List<ImportedShare> shares = KeyUtils.generateShares(this.keyType, (options.serverTimeOffset == null) ? 0 : options.serverTimeOffset, Arrays.asList(nodeIndexes), Arrays.asList(nodePubKeys), newPrivateKey);

        return TorusUtils.retrieveOrImportShare(this.defaultHost, this.options.serverTimeOffset, this.options.enableOneKey, this.defaultHost, this.options.network, this.options.clientId, endpoints, verifier, verifierParams, idToken, shares.toArray(new ImportedShare[0]), this.apiKey, params);
    }
}
