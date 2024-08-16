package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.helpers.KeyUtils.getOrderOfCurve;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.gson.Gson;

import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCErrorInfo;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.PubKey;
import org.torusresearch.torusutils.apis.requests.CommitmentRequestParams;
import org.torusresearch.torusutils.apis.requests.GetMetadataParams;
import org.torusresearch.torusutils.apis.requests.GetOrSetKeyParams;
import org.torusresearch.torusutils.apis.requests.ShareRequestItem;
import org.torusresearch.torusutils.apis.requests.ShareRequestParams;
import org.torusresearch.torusutils.apis.responses.CommitmentRequestResult;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.KeyAssignment;
import org.torusresearch.torusutils.apis.responses.ShareRequestResult;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierLookupResponse;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.TorusUtilsExtraParams;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.common.ImportedShare;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyLookupResult;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyResult;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.SessionToken;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;
import org.web3j.crypto.Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import okhttp3.internal.http2.Header;

public class NodeUtils {
    private NodeUtils() {
    }

    public static KeyLookupResult getPubKeyOrKeyAssign(@NotNull String[] endpoints, @NotNull Web3AuthNetwork network, @NotNull String verifier, @NotNull String verifierId, @NotNull String legacyMetdadataHost, @Nullable Integer serverTimeOffset, @Nullable String extendedVerifierId) throws Exception {
        int threshold = (endpoints.length / 2) + 1;

        BigInteger timeOffset = BigInteger.ZERO;
        if (serverTimeOffset != null) {
            timeOffset = BigInteger.valueOf(serverTimeOffset);
        }
        timeOffset = timeOffset.add( new BigInteger(String.valueOf(System.currentTimeMillis() / 1000)));

        GetOrSetKeyParams params = new GetOrSetKeyParams(true, verifier, verifierId, extendedVerifierId, true, true, timeOffset.toString());
        List<CompletableFuture<String>> lookupPromises = new ArrayList<>();
        for (int i = 0; i < endpoints.length; i++) {
            lookupPromises.add(i, APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("GetPubKeyOrKeyAssign",
                    params), false));
        }

        ArrayList<JsonRPCResponse<VerifierLookupResponse>> collected = new ArrayList<>();

        JsonRPCErrorInfo errResult = null;
        KeyResult key = null;
        List<JsonRPCResponse<VerifierLookupResponse>> lookupPubKeys = null;
        GetOrSetNonceResult nonce = null;

        Gson json = new Gson();
        for (CompletableFuture<String> lookup: lookupPromises) {
            try {
                String result = lookup.get();

                @SuppressWarnings({"unchecked"}) // Due to Type Erasure of Generic Types at Runtime. Java does this to ensure code is compatible with pre-generic versions of Java.
                JsonRPCResponse<VerifierLookupResponse> response = json.fromJson(result, JsonRPCResponse.class);
                collected.add(response);
                lookupPubKeys = collected.stream().filter(item -> item.getError() == null && item.getTypedResult(VerifierLookupResponse.class) != null).collect(Collectors.toList());
                errResult = (JsonRPCErrorInfo) NodeUtils.thresholdSame(collected.stream().filter(item -> item.getError() != null).toArray(), threshold);
                ArrayList<KeyResult> normalizedKeys = new ArrayList<>();
                for (JsonRPCResponse<VerifierLookupResponse> item : lookupPubKeys) {
                    VerifierLookupResponse vlr = item.getTypedResult(VerifierLookupResponse.class);
                    normalizedKeys.add(Common.normalizeKeyResult(vlr));
                }
                key = (KeyResult) NodeUtils.thresholdSame(normalizedKeys.toArray(), threshold);
                if (key != null) {
                    break;
                }
            } catch (Exception e) {
                collected.add(null);
            }
        }

        if (key != null && nonce == null && extendedVerifierId == null && !TorusUtils.isLegacyNetorkRouteMap(network)) {
            for (int i = 0; i < lookupPubKeys.size(); i++) {
                JsonRPCResponse<VerifierLookupResponse> x1 = lookupPubKeys.get(i);
                if (x1 != null && x1.getError() == null) {
                    VerifierLookupResponse x1Result = x1.getTypedResult(VerifierLookupResponse.class);
                    String currentNodePubKeyX = Common.padLeft(x1Result.keys[0].pub_key_X,'0',64).toLowerCase();
                    String thresholdPubKeyX = Common.padLeft(key.keys[0].pub_key_X,'0',64).toLowerCase();
                    if (x1Result.keys[0].nonce_data != null) {
                        PubNonce pubNonce = x1Result.keys[0].nonce_data.pubNonce;
                        if (pubNonce != null && currentNodePubKeyX.equals(thresholdPubKeyX)) {
                            nonce = x1Result.keys[0].nonce_data;
                            break;
                        }
                    }
                }
            }

            if (nonce == null) {
                nonce = MetadataUtils.getOrSetSapphireMetadataNonce(legacyMetdadataHost, network, key.keys[0].pub_key_X,key.keys[0].pub_key_Y, null, null, false, null);
                if (nonce.nonce != null) {
                    nonce.nonce = null;
                }
            }
        }

        ArrayList<Integer> serverTimeOffsets = new ArrayList<>();
        ArrayList<Integer> nodeIndexes = new ArrayList<>();
        if (key != null && (nonce != null || extendedVerifierId != null || TorusUtils.isLegacyNetorkRouteMap(network) || errResult != null)) {
            for (int i = 0; i < lookupPubKeys.size(); i++) {
                JsonRPCResponse<VerifierLookupResponse> x1 = lookupPubKeys.get(i);
                VerifierLookupResponse x1Result = x1.getTypedResult(VerifierLookupResponse.class);
                if (x1 != null && x1Result != null) {
                    String currentNodePubKey = x1Result.keys[0].pub_key_X.toLowerCase();
                    String thresholdPubKey = key.keys[0].pub_key_X.toLowerCase();
                    if (currentNodePubKey.equals(thresholdPubKey)) {
                        if (x1Result.node_index != null)
                        {
                            nodeIndexes.add(Integer.valueOf(x1Result.node_index));
                        }
                    }
                    if (x1Result.server_time_offset != null) {
                        serverTimeOffsets.add(Integer.valueOf(x1Result.server_time_offset));
                    } else {
                        serverTimeOffsets.add(0);
                    }
                }
            }
        }

        Integer finalServerTimeOffset = 0;
        if (key != null) {
            finalServerTimeOffset = Common.calculateMedian(serverTimeOffsets);
        }
        return new KeyLookupResult(key, nodeIndexes, finalServerTimeOffset, nonce, errResult);
    }

    public static TorusKey retrieveOrImportShare(@NotNull String legacyMetadataHost, @Nullable Integer serverTimeOffset,
                                                 @NotNull Boolean enableOneKey, @NotNull String allowHost, @NotNull Web3AuthNetwork network,
                                                 @NotNull String clientId, @NotNull String[] endpoints, @NotNull String verifier, @NotNull VerifierParams verifierParams,
                                                 @NotNull String idToken, @Nullable ImportedShare[] importedShares, @NotNull String apiKey, @Nullable String newPrivateKey, @NotNull TorusUtilsExtraParams extraParams
    ) throws Exception {
        int threshold = (endpoints.length / 2) + 1;

        try {
            APIUtils.get(allowHost, new Header[]{new Header("x-api-key", apiKey), new Header("Origin", verifier), new Header("verifier", verifier), new Header("verifierid", verifierParams.verifier_id), new Header("network", network.name().toLowerCase()),
                    new Header("clientid", clientId), new Header("enablegating", "true")}, true).get();
        } catch (Exception e) {
            throw TorusUtilError.GATING_ERROR;
        }

        KeyPair sessionAuthKey = KeyUtils.generateKeyPair();
        String sessionAuthKeySerialized = Common.padLeft(Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())),'0', 64);
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
            try {
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
            } catch (Exception e) {
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
            String result = APIUtils.post(endpoints[NodeUtils.getProxyCoordinatorEndpointIndex(endpoints, verifier, verifierParams.verifier_id)], req, true).get();
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
            thresholdPublicKey = NodeUtils.thresholdSame(Arrays.stream(shares).filter(item -> item.keys.length > 0).map(item -> item.keys[0].public_key).toArray(PubKey[]::new), threshold);
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
                try {
                    @SuppressWarnings({"unchecked"}) // Due to Type Erasure of Generic Types at Runtime. Java does this to ensure code is compatible with pre-generic versions of Java.
                    JsonRPCResponse<ShareRequestResult> response = json.fromJson(item.get(), JsonRPCResponse.class);

                    if (response != null && response.getError() == null) {
                        shareResponses.add(response.getTypedResult(ShareRequestResult.class));
                    }

                    thresholdPublicKey = NodeUtils.thresholdSame(shareResponses.stream().filter(res -> res.keys.length > 0).map(res -> res.keys[0].public_key).toArray(PubKey[]::new), threshold);

                    if (thresholdPublicKey != null) {
                        break;
                    }
                } catch (Exception e) {
                    // Continue to try next result
                }
            }
        }

        if (thresholdPublicKey == null) {
            throw TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
        }

        ArrayList<String> serverTimeOffsets = new ArrayList<>();

        for (ShareRequestResult item : shareResponses) {
            if (thresholdNonceData == null && verifierParams.extended_verifier_id == null) {
                String currentPubKeyX = Common.padLeft(item.keys[0].public_key.getX(), '0', 64);
                String thresholdPubKeyX = Common.padLeft(thresholdPublicKey.getX(), '0', 64);
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
        Integer serverOffsetResponse = (serverTimeOffset != null) ? serverTimeOffset : Common.calculateMedian(serverOffsetTimes);

        if (thresholdNonceData == null && verifierParams.extended_verifier_id == null && !TorusUtils.isLegacyNetorkRouteMap(network)) {
            thresholdNonceData = MetadataUtils.getOrSetSapphireMetadataNonce(legacyMetadataHost, network, thresholdPublicKey.getX(), thresholdPublicKey.getY(), serverOffsetResponse, null, false, null);
        }

        int thresholdReqCount = (importedShares != null && importedShares.length > 0) ? endpoints.length : threshold;

        if (!(shareResponses.size() >= thresholdReqCount && thresholdPublicKey != null && (thresholdNonceData != null || verifierParams.extended_verifier_id != null || TorusUtils.isLegacyNetorkRouteMap(network)))) {
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

            if (item.session_token_sigs != null && item.session_token_sigs.length > 0) {
                if (item.session_token_sig_metadata != null && item.session_token_sig_metadata.length > 0) {
                    String decrypted = MetadataUtils.decryptNodeData(item.session_token_sig_metadata[0], item.session_token_sigs[0], sessionAuthKeySerialized);
                    sessionTokenSigs.add(decrypted);
                } else {
                    sessionTokenSigs.add(item.session_token_sigs[0]);
                }
            }

            if (item.session_token_sigs != null && item.session_tokens.length > 0) {
                if (item.session_token_metadata != null && item.session_token_metadata.length > 0) {
                    String decrypted = MetadataUtils.decryptNodeData(item.session_token_metadata[0], item.session_tokens[0], sessionAuthKeySerialized);
                    sessionTokens.add(decrypted);
                } else {
                    sessionTokens.add(item.session_tokens[0]);
                }
            }

            if (item.keys.length > 0) {
                KeyAssignment latestKey = item.keys[0];
                nodeIndexes.add(latestKey.node_index);
                String decoded = new String(Base64.getDecoder().decode(latestKey.share.getBytes(StandardCharsets.UTF_8)));
                String decryped = MetadataUtils.decryptNodeData(latestKey.share_metadata, decoded, sessionAuthKeySerialized);
                shares.add(decryped);
            }
        }

        if (verifierParams.extended_verifier_id == null && sessionTokenSigs.size() < threshold) {
            throw TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
        }

        if (verifierParams.extended_verifier_id == null && sessionTokens.size() < threshold) {
            throw TorusUtilError.RUNTIME_ERROR("Insufficient number of signatures from nodes");
        }

        for (int i = 0; i < sessionTokens.size(); i++) {
            String token = sessionTokens.get(i);
            if (token != null) {
                // decode token, can be either hex or base64
                try {
                    byte[] tokenBytes = Hex.decode(token);
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

        List<List<Integer>> allCombis = Common.kCombinations(elements, threshold);

        BigInteger privateKey = null;
        for (int j = 0; j < allCombis.size(); j++) {
            List<Integer> currentCombi = allCombis.get(j);
            Map<Integer, String> currentCombiShares = decryptedShares.entrySet().stream().filter(entry -> currentCombi.contains(entry.getKey())).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            BigInteger derivedPrivateKey = Lagrange.lagrangeInterpolation(new ArrayList<>(currentCombiShares.values()).stream().map(cs -> new BigInteger(cs, 16)).toArray(BigInteger[]::new), new ArrayList<>(currentCombiShares.keySet()).stream().map(is -> new BigInteger(String.valueOf(is))).toArray(BigInteger[]::new));
            if (derivedPrivateKey == null) {
                continue;
            }
            String decryptedPublicKey = KeyUtils.privateToPublic(derivedPrivateKey);
            String[] derivedPublicKeyCoords = KeyUtils.getPublicKeyCoords(decryptedPublicKey);
            String thresholdPubKeyX = Common.padLeft(thresholdPublicKey.getX(), '0', 64);
            String thresholdPubKeyY = Common.padLeft(thresholdPublicKey.getY(), '0', 64);
            if (derivedPublicKeyCoords[0].equalsIgnoreCase(thresholdPubKeyX) && derivedPublicKeyCoords[1].equalsIgnoreCase(thresholdPubKeyY)) {
                privateKey = derivedPrivateKey;
                break;
            }
        }

        if (privateKey == null) {
            throw TorusUtilError.PRIVATE_KEY_DERIVE_FAILED;
        }

        String thesholdIsNewKey = thresholdSame(isNewKeys.toArray(new String[0]), threshold);

        String oAuthKey = Common.padLeft(privateKey.toString(16), '0', 64);
        String oAuthPublicKey = KeyUtils.privateToPublic(privateKey);
        String[] oAuthPublicKeyCoords = KeyUtils.getPublicKeyCoords(oAuthPublicKey);
        BigInteger metadataNonce = (thresholdNonceData != null && thresholdNonceData.nonce != null) ? new BigInteger(Common.padLeft(thresholdNonceData.nonce, '0', 64), 16) : BigInteger.ZERO;
        String finalPublicKey = null;
        PubNonce pubNonce = null;
        TypeOfUser typeOfUser = TypeOfUser.v1;

        if (verifierParams.extended_verifier_id != null) {
            typeOfUser = TypeOfUser.v2;
            finalPublicKey = oAuthPublicKey;
        } else if (TorusUtils.isLegacyNetorkRouteMap(network)) {
            if (enableOneKey) {
                Boolean isNewKey = (!(thesholdIsNewKey != null && thesholdIsNewKey.equalsIgnoreCase("true")));
                GetOrSetNonceResult nonce = MetadataUtils.getOrSetNonce(legacyMetadataHost, thresholdPublicKey.getX(), thresholdPublicKey.getY(), serverOffsetResponse, oAuthKey, isNewKey, null);
                metadataNonce = (nonce.nonce != null) ? new BigInteger(Common.padLeft(nonce.nonce, '0', 64), 16) : BigInteger.ZERO;
                typeOfUser = (nonce.typeOfUser != null) ? nonce.typeOfUser : TypeOfUser.v1;

                if (typeOfUser == TypeOfUser.v2) {
                    pubNonce = nonce.pubNonce;
                    if (pubNonce != null && !pubNonce.x.isEmpty() && !pubNonce.y.isEmpty()) {
                        String pubNonceKey = KeyUtils.getPublicKeyFromCoords(pubNonce.x, pubNonce.y, true);
                        finalPublicKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPublicKey, pubNonceKey), false);
                    } else {
                        throw TorusUtilError.RUNTIME_ERROR("Public nonce is missing");
                    }
                } else {
                    typeOfUser = TypeOfUser.v1;
                    metadataNonce = new BigInteger(Common.padLeft(MetadataUtils.getMetadata(legacyMetadataHost, new GetMetadataParams(oAuthPublicKeyCoords[0], oAuthPublicKeyCoords[1])).message, '0', 64), 16);
                    BigInteger privateKeyWithNonce = new BigInteger(Common.padLeft(oAuthKey, '0', 64), 16).add(metadataNonce);
                    finalPublicKey = KeyUtils.privateToPublic(privateKeyWithNonce);
                }
            } else {
                // typeOfUser = TypeOfUser.v1; Already assigned previously, left here for clarity
                metadataNonce = new BigInteger(Common.padLeft(MetadataUtils.getMetadata(legacyMetadataHost, new GetMetadataParams(oAuthPublicKeyCoords[0], oAuthPublicKeyCoords[1])).message, '0', 64), 16);
                BigInteger privateKeyWithNonce = new BigInteger(Common.padLeft(oAuthKey, '0', 64), 16).add(metadataNonce);
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
                throw TorusUtilError.PUB_NONCE_MISSING; // TODO: Fix this
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
            finalPrivKey = Common.padLeft(privateKeyWithNonce.toString(16), '0', 64);

        }

        // This is a sanity check to make doubly sure we are returning the correct private key after importing a share
        if (isImportShareReq) {
            if (newPrivateKey == null) {
                throw TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
            } else {
                if (!finalPrivKey.equalsIgnoreCase(Common.padLeft(newPrivateKey, '0', 64))) {
                    throw  TorusUtilError.RETRIEVE_OR_IMPORT_SHARE_ERROR;
                }
            }
        }

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

    public static <T> T thresholdSame(@NotNull T[] arr, int threshold) throws JsonProcessingException {
        HashMap<String, Integer> hashMap = new HashMap<>();
        for (T s : arr) {
            ObjectMapper objectMapper = new ObjectMapper()
                    .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
            String value = objectMapper.writeValueAsString(s);
            Integer index = hashMap.get(value);
            if (index != null) {
                hashMap.put(value, index+1);
            } else {
                hashMap.put(value, 0);
            }
            if (hashMap.get(value) != null && hashMap.get(value) == threshold) {
                return s;
            }
        }
        return null;
    }

    @SuppressWarnings("unused")
    public static String thresholdSame(@NotNull List<String> list, int threshold) throws JsonProcessingException {
        String[] arr = new String[list.size()];
        list.toArray(arr);
        return NodeUtils.thresholdSame(arr, threshold);
    }

    public static int getProxyCoordinatorEndpointIndex(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId) {
        String verifierIdString = verifier + verifierId;
        String hashedVerifierId = Hash.sha3(verifierIdString).replace("0x", "");
        BigInteger proxyEndPointNum = new BigInteger(hashedVerifierId, 16).mod(BigInteger.valueOf(endpoints.length));
        return proxyEndPointNum.intValue();
    }
}
