package org.torusresearch.torusutils;

import static org.torusresearch.fetchnodedetails.types.Utils.METADATA_MAP;
import static org.torusresearch.torusutils.helpers.Utils.isLegacyNetorkRouteMap;

import com.google.gson.Gson;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCRequest;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierKey;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.LegacyVerifierLookupResponse;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;
import org.torusresearch.torusutils.helpers.encoding.Base64;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.helpers.Utils;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.GetMetadataParams;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.MetadataResponse;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.SetData;
import org.torusresearch.torusutils.types.TorusKeyType;
import org.torusresearch.torusutils.types.TorusUtilsExtraParams;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.common.ImportedShare;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyLookupResult;
import org.torusresearch.torusutils.types.common.KeyLookup.KeyResult;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TorusOptions;
import org.torusresearch.torusutils.types.common.TorusPublicKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;
import org.torusresearch.torusutils.types.common.meta.MetadataParams;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import io.reactivex.annotations.Nullable;

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
        if (torusKey.metadata.typeOfUser == TypeOfUser.v1) {
            return (torusKey.finalKeyData.privKey == null || torusKey.finalKeyData.privKey.isEmpty()) ?  torusKey.oAuthKeyData.privKey : torusKey.finalKeyData.privKey;
        }
        return torusKey.oAuthKeyData.privKey;
    }

    public static CompletableFuture<TorusKey> retrieveOrImportShare(@NotNull String legacyMetadataHost, @NotNull Integer serverTimeOffset,
                                                                    @NotNull Boolean enableOneKey, @NotNull String allowHost, @NotNull Web3AuthNetwork network,
                                                                    @NotNull String clientId, @NotNull String[] endpoints, @NotNull String verifier, @NotNull VerifierParams verifierParams,
                                                             @NotNull String idToken, @Nullable ImportedShare[] importedShares, @Nullable String apiKey, @Nullable TorusUtilsExtraParams extraParams
                                                             ) {
        String finaApiKey = (apiKey == null) ? "torus-default" : apiKey;

        /*try {

            APIUtils.get(legacyMetadataHost, new Header[]{new Header("Origin", verifier), new Header("verifier", verifier), new Header("verifierid", verifierParams.verifier_id), new Header("network", network.name().toLowerCase()),
                    new Header("clientid", clientId), new Header("enablegating", "true")}, true).get();
            List<CompletableFuture<String>> promiseArr = new ArrayList<>();
            Set<SessionToken> sessionTokenData = new HashSet<>();
            Set<Integer> nodeIndexs = new HashSet<>();
            // generate temporary private and public key that is used to secure receive shares
            KeyPair sessionAuthKey = KeyUtils.generateKeyPair();
            String pubKey = Hex.toHexString(KeyUtils.serializePublicKey(sessionAuthKey.getPublic(), false));
            String[] pubKeyCoords = KeyUtils.getPublicKeyCoords(pubKey);
            String pubKeyX = pubKeyCoords[0];
            String pubKeyY = pubKeyCoords[1];

            String tokenCommitment = Hash.sha3String(idToken);

            int minRequiredCommitmments = (endpoints.length * 3 / 4) + 1;
            int threshold = (endpoints.length / 2) + 1;

            boolean isImportShareReq = false;
            if (importedShares != null && importedShares.length > 0) {
                if (importedShares.length != endpoints.length) {
                    throw new Error("Invalid imported shares length");
                }
                isImportShareReq = true;
            }

            // make commitment requests to endpoints
            for (int i = 0; i < endpoints.length; i++) {
                CompletableFuture<String> p = APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("CommitmentRequest", new CommitmentRequestParams("mug00", tokenCommitment.substring(2), pubKeyX, pubKeyY, String.valueOf(System.currentTimeMillis()), verifier)), false);
                promiseArr.add(i, p);
            }

            // send share request once minRequiredCommitmments number of commitment requests have completed
            boolean finalIsImportShareReq = isImportShareReq;
            return new Some<>(promiseArr, (resultArr, commitmentsResolved) -> {
                List<String> completedRequests = new ArrayList<>();
                int received = 0;
                for (CompletableFuture<String> result : promiseArr) {
                    try {
                        if (result.get() != null && !result.get().isEmpty()) {
                            received += 1;
                            completedRequests.add(result.get());
                            if (!finalIsImportShareReq) {
                                if (received >= minRequiredCommitmments) {
                                    break;
                                }
                            }
                        }
                    } catch (Exception ex) {
                        // ignore ex
                    }
                }

                // Return List<String> instead
                CompletableFuture<List<String>> completableFuture = new CompletableFuture<>();
                if (!finalIsImportShareReq  && completedRequests.size() < minRequiredCommitmments) {
                    completableFuture.completeExceptionally(new PredicateFailedException("insufficient responses for commitments"));
                } else if (finalIsImportShareReq && completedRequests.size() < Arrays.stream(endpoints).count()) {
                    completableFuture.completeExceptionally(new PredicateFailedException("insufficient responses for commitments"));
                }

                completableFuture.complete(completedRequests);
                return completableFuture;
            }).getCompletableFuture().thenComposeAsync(responses -> {
                try {
                    List<CompletableFuture<String>> promiseArrRequests = new ArrayList<>();
                    List<String> nodeSigs = new ArrayList<>();
                    for (String respons : responses) {
                        if (respons != null && !respons.isEmpty()) {
                            Gson gson = new Gson();
                            try {
                                JsonRPCResponse nodeSigResponse = gson.fromJson(respons, JsonRPCResponse.class);
                                if (nodeSigResponse != null && nodeSigResponse.getResult() != null) {
                                    nodeSigs.add(Utils.convertToJsonObject(nodeSigResponse.getResult()));
                                }
                            } catch (JsonSyntaxException e) {
                                // discard this, we don't care
                            }
                        }
                    }
                    CommitmentRequestResult[] commitments = new CommitmentRequestResult[nodeSigs.size()];
                    for (int l = 0; l < nodeSigs.size(); l++) {
                        Gson gson = new Gson();
                        commitments[l] = gson.fromJson(nodeSigs.get(l), CommitmentRequestResult.class);
                    }
                    if (finalIsImportShareReq) {
                        List<ShareRequestItem> shareRequestItems = new ArrayList<>();
                        for (int i = 0; i < endpoints.length; i++) {
                            ShareRequestItem shareRequestItem = new ShareRequestItem(verifier, verifierParams.verifier_id, verifierParams.extended_verifier_id,
                                    idToken, extraParams, commitments, importedShares[i].getOauth_pub_key_x(), importedShares[i].getOauth_pub_key_y(),
                                    importedShares[i].getSigning_pub_key_x(), importedShares[i].getSigning_pub_key_y(), importedShares[i].getEncryptedShare(),
                                    importedShares[i].getEncryptedShareMetadata(), importedShares[i].getNode_index(), importedShares[i].getKey_type(),
                                    importedShares[i].getNonce_data(), importedShares[i].getNonce_signature(), verifierParams.sub_verifier_ids, verifierParams.verify_params, endpoints[i]);
                            shareRequestItems.add(shareRequestItem);
                        }
                        String req = APIUtils.generateJsonRPCObject("ImportShares", new ShareRequestParams(shareRequestItems.toArray(new ShareRequestItem[0]), "0")); // TODO: Fix this client_time
                        CompletableFuture<String> result = APIUtils.post(endpoints[Utils.getProxyCoordinatorEndpointIndex(endpoints, verifier, verifierParams.verifier_id)], req, true);
                        System.out.println(result.get());
                        promiseArrRequests.add(result);
                    } else {
                        for (String endpoint : endpoints) {
                            ShareRequestItem shareRequestItem = new ShareRequestItem(verifier, verifierParams.verifier_id, verifierParams.extended_verifier_id,
                                    idToken, extraParams, commitments, null, null,
                                    null, null, null,
                                    null, null, null,
                                    null, null, verifierParams.sub_verifier_ids, verifierParams.verify_params, null);

                            List<ShareRequestItem> shareRequestItems = new ArrayList<>();
                            shareRequestItems.add(shareRequestItem);
                            String req = APIUtils.generateJsonRPCObject("GetShareOrKeyAssign", new ShareRequestParams(shareRequestItems.toArray(new ShareRequestItem[0]), "0")); // TODO: Fix client time
                            promiseArrRequests.add(APIUtils.post(endpoint, req, true));
                        }
                    }
                    return new Some<>(promiseArrRequests, (shareResponses, predicateResolved) -> {
                        try {
                            BigInteger privateKey = null;
                            List<ShareRequestResult> completedResponses = new ArrayList<>();
                            Gson gson = new Gson();
                            List<CommitmentRequestResult> commitmentResults = new ArrayList<>();
                            List<KeyLookupResult> keyAssignResults = new ArrayList<>();
                            List<String> completedResponsesPubKeys = new ArrayList<>();
                            GetOrSetNonceResult thresholdNonceData = null;
                            ArrayList<String> isNewKeyArr = new ArrayList<>();
                            int shareResponseSize = 0;

                            for (CompletableFuture<String> shareResponse : promiseArrRequests) {
                                if (shareResponse.get() != null && !shareResponse.get().equals("")) {
                                    try {
                                        ShareRequestResult shareResponseJson = gson.fromJson(shareResponse.get(), ShareRequestResult.class);
                                        completedResponses.add(shareResponseJson);
                                    } catch (JsonSyntaxException e) {
                                        // discard this, we don't care
                                    }
                                }
                            }

                            if (finalIsImportShareReq) {
                                for (ShareRequestResult x : completedResponses) {
                                    JSONArray jsonArray = new JSONArray(x);
                                    shareResponseSize = jsonArray.length();
                                    for (int i = 0; i < jsonArray.length(); i++) {
                                        KeyLookupResult keyAssignResult = gson.fromJson(String.valueOf(jsonArray.getJSONObject(i)), KeyLookupResult.class);
                                        keyAssignResults.add(keyAssignResult);
                                        if (keyAssignResult == null || keyAssignResult.keyResult == null || keyAssignResult.keyResult.keys.length == 0) {
                                            return null;
                                        }
                                        VerifierKey keyAssignResultFirstKey = keyAssignResult.keyResult.keys[0];
                                        completedResponsesPubKeys.add(Utils.convertToJsonObject(KeyUtils.getPublicKeyFromCoords(keyAssignResultFirstKey.pub_key_X, keyAssignResultFirstKey.pub_key_Y, false)));
                                        if (Utils.isSapphireNetwork(network.name().toLowerCase())) {
                                            PubNonce pubNonce = keyAssignResultFirstKey.nonce_data.pubNonce;
                                            if (pubNonce != null && pubNonce.x != null) {
                                                thresholdNonceData = keyAssignResult.keyResult.keys[0].nonce_data;
                                            }
                                        }
                                    }
                                }

                                String thresholdPublicKeyString = Utils.thresholdSame(completedResponsesPubKeys, threshold);
                                PubKey thresholdPubKey = null;

                                if (thresholdPublicKeyString == null) {
                                    throw new RuntimeException("Invalid result from nodes, threshold number of public key results are not matching");
                                }
                                // If both thresholdNonceData and extended_verifier_id are not available,
                                // then we need to throw an error; otherwise, the address would be incorrect.
                                if (thresholdNonceData == null && verifierParams.extended_verifier_id == null &&
                                        !LEGACY_NETWORKS_ROUTE_MAP.containsKey(network)) {
                                    throw new RuntimeException(String.format(
                                            "Invalid metadata result from nodes, nonce metadata is empty for verifier: %s and verifierId: %s",
                                            verifier, verifierParams.verifier_id)
                                    );
                                }

                                if (!thresholdPublicKeyString.isEmpty()) {
                                    thresholdPubKey = gson.fromJson(thresholdPublicKeyString, PubKey.class);
                                }

                                for (KeyLookupResult item : keyAssignResults) {
                                    if (thresholdNonceData == null && verifierParams.extended_verifier_id == null) {
                                        VerifierKey keyAssignment = item.keyResult.keys[0];
                                        String currentPubKeyX = Utils.addLeading0sForLength64(keyAssignment.pub_key_X).toLowerCase();
                                        String thresholdPubKeyX = Utils.addLeading0sForLength64(thresholdPubKey.getX()).toLowerCase();
                                        PubNonce pubNonce = keyAssignment.nonce_data != null ? keyAssignment.nonce_data.pubNonce : null;
                                        if (pubNonce != null && currentPubKeyX.equals(thresholdPubKeyX)) {
                                            thresholdNonceData = keyAssignment.nonce_data;
                                        }
                                    }
                                }

                                List<Integer> serverTimeOffsets = new ArrayList<>();
                                for (KeyLookupResult item : keyAssignResults) {
                                    serverTimeOffsets.add(item.server_time_offset);
                                }

                                Integer serverTimeOffsetResponse = (serverTimeOffset != null) ? serverTimeOffset : calculateMedian(serverTimeOffsets);

                                if (thresholdNonceData == null && verifierParams.extended_verifier_id == null && !LEGACY_NETWORKS_ROUTE_MAP.containsKey(network)) {
                                    GetOrSetNonceResult metadataNonce = TorusUtils.getNonce(legacyMetadataHost, privateKey, serverTimeOffsetResponse);
                                    thresholdNonceData = metadataNonce;
                                }

                                List<String> shares = new ArrayList<>();
                                List<String> sessionTokenSigs = new ArrayList<>();
                                List<String> sessionTokens = new ArrayList<>();
                                List<SessionToken> sessionTokenDatas = new ArrayList<>();
                                List<BigInteger> serverTimeOffsetResponses = new ArrayList<>();
                                ShareRequestResult currentShareResponse;

                                for (int i = 0; i < keyAssignResults.size(); i++) {
                                    if (keyAssignResults.get(i) != null) {
                                        currentShareResponse = completedResponses.get(i);
                                        isNewKeyArr.add(currentShareResponse.is_new_key.toString());
                                        serverTimeOffsetResponses.add(currentShareResponse.server_time_offset != null ? new BigInteger(currentShareResponse.server_time_offset) : BigInteger.ZERO);

                                        if (currentShareResponse.session_token_sigs != null && currentShareResponse.session_token_sigs.length > 0) {
                                            // Decrypt sessionSig if enc metadata is sent
                                            EciesHexOmitCipherText[] sessionTokenSigMetaData = currentShareResponse.session_token_metadata;
                                            if (sessionTokenSigMetaData != null && sessionTokenSigMetaData[0] != null && sessionTokenSigMetaData[0].getEphemPublicKey() != null) {
                                                try {
                                                    String decrypted = Encryption.decryptNodeData(sessionTokenSigMetaData[0], currentShareResponse.session_token_sigs[0], Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())));
                                                    sessionTokenSigs.add(decrypted);
                                                } catch (Exception ex) {
                                                    System.out.println("session token sig decryption" + ex);
                                                    return null;
                                                }
                                            } else {
                                                sessionTokenSigs.add(currentShareResponse.session_token_sigs[0]);
                                            }
                                        } else {
                                            sessionTokenSigs.add(null);
                                        }

                                        if (currentShareResponse.session_tokens != null && currentShareResponse.session_tokens.length > 0) {
                                            // Decrypt sessionToken if enc metadata is sent
                                            EciesHexOmitCipherText[] sessionTokenMetaData = currentShareResponse.session_token_metadata;
                                            if (sessionTokenMetaData != null && sessionTokenMetaData[0] != null &&
                                                    currentShareResponse.session_token_metadata[0].getEphemPublicKey() != null) {
                                                try {
                                                    String decrypted = Encryption.decryptNodeData(sessionTokenMetaData[0], currentShareResponse.session_tokens[0], Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())));
                                                    sessionTokens.add(decrypted);
                                                } catch (Exception ex) {
                                                    System.out.println("share decryption" + ex);
                                                    return null;
                                                }
                                            } else {
                                                sessionTokens.add(currentShareResponse.session_tokens[0]);
                                            }
                                        } else {
                                            sessionTokens.add(null);
                                        }

                                        if (currentShareResponse.keys != null && currentShareResponse.keys.length > 0) {
                                            KeyAssignment firstKey = currentShareResponse.keys[0];
                                            if (firstKey.node_index != null) {
                                                nodeIndexs.add(firstKey.node_index);
                                            }
                                            if (firstKey.share_metadata != null) {
                                                try {
                                                    String cipherTextHex = new String(Base64.decode(firstKey.share), StandardCharsets.UTF_8);
                                                    String decrypted = Encryption.decryptNodeData(firstKey.share_metadata, cipherTextHex, Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())));
                                                    shares.add(decrypted);
                                                } catch (Exception e) {
                                                    e.printStackTrace();
                                                }
                                            } else {
                                                nodeIndexs.add(null);
                                                shares.add(null);
                                            }
                                        }
                                    }
                                }

                                List<String> validSigs = sessionTokenSigs.stream()
                                        .filter(Objects::nonNull)
                                        .collect(Collectors.toList());

                                if (validSigs.size() < threshold) {
                                    throw new RuntimeException("Insufficient number of signatures from nodes");
                                }

                                List<String> validTokens = sessionTokens.stream()
                                        .filter(Objects::nonNull)
                                        .collect(Collectors.toList());

                                if (validTokens.size() < threshold) {
                                    throw new RuntimeException("Insufficient number of tokens from nodes");
                                }

                                for (int i = 0; i < sessionTokens.size(); i++) {
                                    String item = sessionTokens.get(i);
                                    if (item == null) {
                                        sessionTokenDatas.add(null);
                                    } else {
                                        sessionTokenDatas.add(new SessionToken(
                                                Base64.encodeBytes(item.getBytes()),
                                                Base64.encodeBytes(sessionTokenSigs.get(i).getBytes()),
                                                completedResponses.get(i).node_pubx,
                                                completedResponses.get(i).node_puby
                                        ));
                                    }
                                }

                                Map<Integer, String> decryptedShares = new HashMap<>();
                                for (int i = 0; i < shares.size(); i++) {
                                    String item = shares.get(i);
                                    if (item != null && !item.isEmpty()) {
                                        decryptedShares.put(i, item);
                                    }
                                }

                                List<Integer> elements = new ArrayList<>();
                                for (int i = 0; i <= Collections.max(decryptedShares.keySet()); i++) {
                                    elements.add(i);
                                }

                                List<List<Integer>> allCombis = Utils.kCombinations(elements, threshold);

                                for (List<Integer> currentCombi : allCombis) {
                                    Map<Integer, String> currentCombiShares = decryptedShares.entrySet().stream()
                                            .filter(e -> currentCombi.contains(e.getKey()))
                                            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
                                    List<String> sharesList = new ArrayList<>(currentCombiShares.values());
                                    List<BigInteger> shareListBigInteger = new ArrayList<>();
                                    for (String share: sharesList) {
                                        shareListBigInteger.add(new BigInteger(share, 16));
                                    }
                                    List<Integer> indices = new ArrayList<>(currentCombiShares.keySet());
                                    List<BigInteger> indicesBigInteger = new ArrayList<>();
                                    for (Integer index: indices) {
                                        indicesBigInteger.add(BigInteger.valueOf(index.intValue()));
                                    }
                                    BigInteger derivedPrivateKey = Lagrange.lagrangeInterpolation(shareListBigInteger.toArray(new BigInteger[0]), indicesBigInteger.toArray(new BigInteger[0]));
                                    assert derivedPrivateKey != null;
                                    PublicKey derivedECKeyPair = KeyUtils.privateToPublic(KeyUtils.deserializePrivateKey(Hex.decode(derivedPrivateKey.toString(16))));
                                    String derivedPubKeyString = Hex.toHexString(KeyUtils.serializePublicKey(derivedECKeyPair, false)).substring(2);
                                    String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2); // this will be padded
                                    String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);  // this will be padded
                                    if (new BigInteger(derivedPubKeyX, 16).compareTo(new BigInteger(thresholdPubKey.getX(), 16)) == 0 && new BigInteger(derivedPubKeyY, 16).compareTo(new BigInteger(thresholdPubKey.getY(), 16)) == 0) {
                                        privateKey = derivedPrivateKey;
                                        break;
                                    }
                                }
                                CompletableFuture<PrivateKeyWithNonceResult> response = new CompletableFuture<>();
                                if (privateKey == null) {
                                    response.completeExceptionally(new PredicateFailedException("could not derive private key"));
                                } else {
                                    response.complete(new PrivateKeyWithNonceResult(privateKey, thresholdNonceData, serverTimeOffsetResponse));
                                }
                                return response;
                            } else {
                                // check if threshold number of nodes have returned the same user public key
                                for (ShareRequestResult x : completedResponses) {
                                    if (x.keys == null || x.keys.length == 0) {
                                        return null;
                                    }
                                    KeyAssignment keyAssignResultFirstKey = x.keys[0];
                                    completedResponsesPubKeys.add(Utils.convertToJsonObject(keyAssignResultFirstKey.public_key));
                                    if (Utils.isSapphireNetwork(network.name().toLowerCase())) {
                                        PubNonce pubNonce = keyAssignResultFirstKey.nonce_data.pubNonce;
                                        if (pubNonce != null && pubNonce.x != null) {
                                            thresholdNonceData =x.keys[0].nonce_data;
                                        }
                                    }
                                }
                                String thresholdPublicKeyString = Utils.thresholdSame(completedResponsesPubKeys, threshold);
                                PubKey thresholdPubKey = null;

                                if (thresholdPublicKeyString == null) {
                                    throw new RuntimeException("Invalid result from nodes, threshold number of public key results are not matching");
                                }
                                // If both thresholdNonceData and extended_verifier_id are not available,
                                // then we need to throw an error; otherwise, the address would be incorrect.
                                if (thresholdNonceData == null && verifierParams.extended_verifier_id == null &&
                                        !LEGACY_NETWORKS_ROUTE_MAP.containsKey(network)) {
                                    throw new RuntimeException(String.format(
                                            "Invalid metadata result from nodes, nonce metadata is empty for verifier: %s and verifierId: %s",
                                            verifier, verifierParams.verifier_id)
                                    );
                                }

                                if (!thresholdPublicKeyString.isEmpty()) {
                                    thresholdPubKey = gson.fromJson(thresholdPublicKeyString, PubKey.class);
                                }

                                if (completedResponses.size() >= threshold && thresholdPubKey != null && (thresholdNonceData != null || verifierParams.extended_verifier_id != null ||
                                        LEGACY_NETWORKS_ROUTE_MAP.containsKey(network))) {
                                    HashMap<BigInteger,BigInteger> decryptedShares = new HashMap<>();
                                    List<String> shares = new ArrayList<>();
                                    List<CompletableFuture<String>> sharePromises = new ArrayList<>();
                                    List<CompletableFuture<String>> sessionTokenSigPromises = new ArrayList<>();
                                    List<CompletableFuture<String>> sessionTokenPromises = new ArrayList<>();
                                    List<Integer> serverTimeOffsetResponses = new ArrayList<>();
                                    ShareRequestResult currentShareResponse;
                                    for (int i = 0; i < shareResponses.length; i++) {
                                        if (shareResponses[i] != null && !shareResponses[i].isEmpty()) {
                                            try {
                                                JsonRPCResponse currentJsonRPCResponse = gson.fromJson(shareResponses[i], JsonRPCResponse.class);
                                                if (currentJsonRPCResponse != null && currentJsonRPCResponse.getResult() != null && !currentJsonRPCResponse.getResult().equals("")) {
                                                    if (finalIsImportShareReq) {
                                                        currentShareResponse = completedResponses.get(i);
                                                    } else {
                                                        currentShareResponse = gson.fromJson(Utils.convertToJsonObject(currentJsonRPCResponse.getResult()), ShareRequestResult.class);
                                                    }
                                                    isNewKeyArr.add(currentShareResponse.is_new_key.toString());
                                                    if (currentShareResponse.server_time_offset.isEmpty()) {
                                                        currentShareResponse.server_time_offset = "0";
                                                    }
                                                    serverTimeOffsetResponses.add(currentShareResponse.server_time_offset != null ? Integer.valueOf(currentShareResponse.server_time_offset) : 0);
                                                    if (currentShareResponse.session_token_sigs != null && currentShareResponse.session_token_sigs.length > 0) {
                                                        // Decrypt sessionSig if enc metadata is sent
                                                        EciesHexOmitCipherText[] sessionTokenSigMetaData = currentShareResponse.session_token_metadata;
                                                        if (sessionTokenSigMetaData != null && sessionTokenSigMetaData[0] != null && sessionTokenSigMetaData[0].getEphemPublicKey() != null) {
                                                            try {
                                                                String decrypted = Encryption.decryptNodeData(sessionTokenSigMetaData[0], currentShareResponse.session_token_sigs[0], Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())));
                                                                sessionTokenSigPromises.add(CompletableFuture.completedFuture(decrypted));
                                                            } catch (Exception ex) {
                                                                System.out.println("session token sig decryption" + ex);
                                                                return null;
                                                            }
                                                        } else {
                                                            sessionTokenSigPromises.add(CompletableFuture.completedFuture(currentShareResponse.session_token_sigs[0]));
                                                        }
                                                    } else {
                                                        sessionTokenSigPromises.add(CompletableFuture.completedFuture(null));
                                                    }

                                                    if (currentShareResponse.session_tokens != null && currentShareResponse.session_tokens.length > 0) {
                                                        // Decrypt sessionToken if enc metadata is sent
                                                        EciesHexOmitCipherText[] sessionTokenMetaData = currentShareResponse.session_token_metadata;
                                                        if (sessionTokenMetaData != null && sessionTokenMetaData[0] != null &&
                                                                currentShareResponse.session_token_metadata[0].getEphemPublicKey() != null) {
                                                            try {
                                                                String decrypted = Encryption.decryptNodeData(sessionTokenMetaData[0], currentShareResponse.session_tokens[0], Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())));
                                                                sessionTokenSigPromises.add(CompletableFuture.completedFuture(decrypted));
                                                            } catch (Exception ex) {
                                                                System.out.println("share decryption" + ex);
                                                                return null;
                                                            }
                                                        } else {
                                                            sessionTokenPromises.add(CompletableFuture.completedFuture(currentShareResponse.session_tokens[0]));
                                                        }
                                                    } else {
                                                        sessionTokenPromises.add(CompletableFuture.completedFuture(null));
                                                    }

                                                    if (currentShareResponse.keys != null && currentShareResponse.keys.length > 0) {
                                                        KeyAssignment firstKey = currentShareResponse.keys[0];
                                                        if (firstKey.node_index != null) {
                                                            nodeIndexs.add(firstKey.node_index);
                                                        }
                                                        if (firstKey.share_metadata != null) {
                                                            try {
                                                                String cipherTextHex = new String(Base64.decode(firstKey.share), StandardCharsets.UTF_8);
                                                                String decrypted = Encryption.decryptNodeData(firstKey.share_metadata, cipherTextHex, Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate())));
                                                                shares.add(decrypted);
                                                            } catch (Exception e) {
                                                                e.printStackTrace();
                                                            }
                                                        } else {
                                                            nodeIndexs.add(null);
                                                            sharePromises.add(CompletableFuture.completedFuture(null));
                                                        }
                                                    }
                                                }
                                            } catch (JsonSyntaxException e) {
                                                continue;
                                            }
                                        }
                                    }

                                    List<CompletableFuture<String>> allPromises = new ArrayList<>();
                                    allPromises.addAll(sharePromises);
                                    allPromises.addAll(sessionTokenSigPromises);
                                    allPromises.addAll(sessionTokenPromises);

                                    CompletableFuture.allOf(allPromises.toArray(new CompletableFuture[0])).join();

                                    List<CompletableFuture<String>> sharesResolved = allPromises.subList(0, sharePromises.size());
                                    List<CompletableFuture<String>> sessionSigsResolved = allPromises.subList(sharePromises.size(), sharePromises.size() + sessionTokenSigPromises.size());
                                    List<CompletableFuture<String>> sessionTokensResolved = allPromises.subList(sharePromises.size() + sessionTokenSigPromises.size(), allPromises.size());

                                    List<CompletableFuture<String>> validSigs = new ArrayList<>();
                                    for (CompletableFuture<String> sig : sessionSigsResolved) {
                                        if (sig != null) {
                                            validSigs.add(sig);
                                        }
                                    }

                                    int minThresholdRequired = (int) Math.floor(endpoints.length / 2.0f) + 1;
                                    if (verifierParams.extended_verifier_id != null && validSigs.size() < minThresholdRequired) {
                                        throw new Error("Insufficient number of signatures from nodes, required: " + minThresholdRequired + ", found: " + validSigs.size());
                                    }

                                    List<CompletableFuture<String>> validTokens = new ArrayList<>();
                                    for (CompletableFuture<String> token : sessionTokensResolved) {
                                        if (token != null) {
                                            validTokens.add(token);
                                        }
                                    }

                                    if (verifierParams.extended_verifier_id != null && validTokens.size() < minThresholdRequired) {
                                        throw new Error("Insufficient number of session tokens from nodes, required: " + minThresholdRequired + ", found: " + validTokens.size());
                                    }

                                    for (int index = 0; index < sessionTokensResolved.size(); index++) {
                                        if (sessionSigsResolved.get(index) == null) {
                                            sessionTokenData.add(null);
                                        } else {
                                            if (finalIsImportShareReq) {
                                                CommitmentRequestResult keyAssignResult = commitmentResults.get(index);
                                                sessionTokenData.add(new SessionToken(sessionTokensResolved.get(index).get(),
                                                                sessionSigsResolved.get(index).get(),
                                                                keyAssignResult.nodepubx,
                                                                keyAssignResult.nodepuby
                                                        )
                                                );
                                            } else {
                                                JsonRPCResponse jsonRPCResponse = gson.fromJson(shareResponses[index], JsonRPCResponse.class);
                                                if (jsonRPCResponse != null && jsonRPCResponse.getResult() != null && !jsonRPCResponse.getResult().equals("")) {
                                                    CommitmentRequestResult keyAssignResult = gson.fromJson(Utils.convertToJsonObject(jsonRPCResponse.getResult()), CommitmentRequestResult.class);
                                                    if (keyAssignResult != null) {
                                                        sessionTokenData.add(new SessionToken(sessionTokensResolved.get(index).get(),
                                                                        sessionSigsResolved.get(index).get(),
                                                                        keyAssignResult.nodepubx,
                                                                        keyAssignResult.nodepuby
                                                                )
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    List<Integer> serverOffsetTimes = serverTimeOffsetResponses;

                                    Integer serverTimeOffsetResponse = !Objects.equals(serverTimeOffset, BigInteger.ZERO) ?
                                            serverTimeOffset : calculateMedian(serverOffsetTimes);

                                    if (predicateResolved.get()) return null;

                                    List<Integer> _nodeIndexs = new ArrayList<>(nodeIndexs);
                                    for (int index = 0; index < shares.size(); index++) {
                                        Object curr = shares.get(index);
                                        if (curr != null) {
                                            decryptedShares.put(new BigInteger(_nodeIndexs.get(index).toString()), new BigInteger(curr.toString()));
                                        }
                                    }

                                    List<List<Integer>> allCombis = Utils.kCombinations(decryptedShares.size(), threshold);
                                    for (List<Integer> currentCombi : allCombis) {
                                        List<BigInteger> currentCombiSharesIndexes = new ArrayList<>();
                                        List<BigInteger> currentCombiSharesValues = new ArrayList<>();
                                        for (int i = 0; i < decryptedShares.size(); i++) {
                                            if (currentCombi.contains(i)) {
                                                currentCombiSharesIndexes.add(new BigInteger(String.valueOf(i)));
                                                currentCombiSharesValues.add(decryptedShares.get(new BigInteger(String.valueOf(i))));
                                            }
                                        }
                                        BigInteger derivedPrivateKey = Lagrange.lagrangeInterpolation(currentCombiSharesValues.toArray(new BigInteger[0]), currentCombiSharesIndexes.toArray(new BigInteger[0]));
                                        assert derivedPrivateKey != null;
                                        ECKeyPair derivedECKeyPair = ECKeyPair.create(derivedPrivateKey);
                                        String derivedPubKeyString = Utils.padLeft(derivedECKeyPair.getPublicKey().toString(16), '0', 128);
                                        String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2); // this will be padded
                                        String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);  // this will be padded
                                        if (new BigInteger(derivedPubKeyX, 16).compareTo(new BigInteger(thresholdPubKey.getX(), 16)) == 0 && new BigInteger(derivedPubKeyY, 16).compareTo(new BigInteger(thresholdPubKey.getY(), 16)) == 0) {
                                            privateKey = derivedPrivateKey;
                                            break;
                                        }
                                    }
                                    CompletableFuture<PrivateKeyWithNonceResult> response = new CompletableFuture<>();
                                    if (privateKey == null) {
                                        response.completeExceptionally(new PredicateFailedException("could not derive private key"));
                                    } else {
                                        response.complete(new PrivateKeyWithNonceResult(privateKey, thresholdNonceData, serverTimeOffsetResponse));
                                    }
                                    return response;
                                } else {
                                    CompletableFuture<PrivateKeyWithNonceResult> response = new CompletableFuture<>();
                                    response.completeExceptionally(new PredicateFailedException("could not get enough shares"));
                                    return response;
                                }
                            }
                        } catch (Exception ex) {
                            CompletableFuture<PrivateKeyWithNonceResult> cfRes = new CompletableFuture<>();
                            cfRes.completeExceptionally(new TorusException("Torus Internal Error", ex));
                            return cfRes;
                        }
                    }).getCompletableFuture();
                } catch (Exception ex) {
                    CompletableFuture<PrivateKeyWithNonceResult> cfRes = new CompletableFuture<>();
                    cfRes.completeExceptionally(new TorusException("Torus Internal Error", ex));
                    return cfRes;
                }
            }).thenComposeAsync((privateKeyWithNonceResult) -> {
                BigInteger privateKey = privateKeyWithNonceResult.getPrivateKey();
                GetOrSetNonceResult thresholdNonceData = privateKeyWithNonceResult.getNonceResult();
                Integer serverTimeOffsetResponse = privateKeyWithNonceResult.getServerTimeOffsetResponse();
                CompletableFuture<TorusKey> cf = new CompletableFuture<>();
                if (privateKey == null) {
                    cf.completeExceptionally(new TorusException("could not derive private key"));
                    return cf;
                }
                try {
                    ECKeyPair derivedECKeyPair = ECKeyPair.create(privateKey);
                    String oAuthPubKey = Utils.padLeft(derivedECKeyPair.getPublicKey().toString(16), '0', 128);
                    String oAuthPubkeyX = oAuthPubKey.substring(0, oAuthPubKey.length() / 2);
                    String oAuthPubkeyY = oAuthPubKey.substring(oAuthPubKey.length() / 2);
                    BigInteger metadataNonce;
                    GetOrSetNonceResult nonceResult = thresholdNonceData;
                    if (thresholdNonceData != null) {
                        metadataNonce = new BigInteger(Utils.isEmpty(thresholdNonceData.nonce) ? "0" : thresholdNonceData.nonce, 16);
                    } else {
                        nonceResult = TorusUtils.getNonce(legacyMetadataHost, privateKey, serverTimeOffsetResponse);
                        metadataNonce = new BigInteger(Utils.isEmpty(nonceResult.nonce) ? "0" : nonceResult.nonce, 16);
                    }
                    List<Integer> nodeIndexes = new ArrayList<>(nodeIndexs);
                    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                    ECPoint finalPubKey = null;
                    PubNonce pubNonce = null;
                    TypeOfUser typeOfUser;
                    if (verifierParams.extended_verifier_id != null && !verifierParams.extended_verifier_id.equals("")) {
                        typeOfUser = TypeOfUser.v2;
                        // for tss key no need to add pub nonce
                        finalPubKey = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                    } else if (LEGACY_NETWORKS_ROUTE_MAP.containsKey(network)) {
                        if (enableOneKey) {
                            nonceResult = TorusUtils.getNonce(legacyMetadataHost,privateKey, serverTimeOffsetResponse);
                            pubNonce = nonceResult.pubNonce;
                            metadataNonce = new BigInteger(Utils.isEmpty(nonceResult.nonce) ? "0" : nonceResult.nonce, 16);
                            typeOfUser = nonceResult.typeOfUser;
                            if (typeOfUser.equals(TypeOfUser.v2)) {
                                typeOfUser = TypeOfUser.v2;
                                ECPoint oAuthPubKeyPoint = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                                ECPoint pubNoncePoint = curve.getCurve().createPoint(new BigInteger(pubNonce.x, 16), new BigInteger(pubNonce.y, 16));
                                finalPubKey = oAuthPubKeyPoint.add(pubNoncePoint);
                            } else {
                                typeOfUser = TypeOfUser.v1;
                                metadataNonce = TorusUtils.getMetadata(legacyMetadataHost, new GetMetadataParams(oAuthPubkeyX, oAuthPubkeyY));
                                BigInteger privateKeyWithNonce = privateKey.add(metadataNonce).mod(secp256k1N);
                                finalPubKey = curve.getG().multiply(privateKeyWithNonce).normalize();
                            }
                        } else {
                            typeOfUser = TypeOfUser.v1;
                            metadataNonce = TorusUtils.getMetadata(legacyMetadataHost,new GetMetadataParams(oAuthPubkeyX, oAuthPubkeyY));
                            BigInteger privateKeyWithNonce = privateKey.add(metadataNonce).mod(secp256k1N);
                            finalPubKey = curve.getG().multiply(privateKeyWithNonce).normalize();
                        }
                    } else {
                        typeOfUser = TypeOfUser.v2;
                        ECPoint oAuthPubKeyPoint = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                        if (nonceResult.pubNonce != null && nonceResult.pubNonce.x.length() > 0 && nonceResult.pubNonce.y.length() > 0) {
                            ECPoint noncePoint = curve.getCurve().createPoint(new BigInteger(nonceResult.pubNonce.x, 16), new BigInteger(nonceResult.pubNonce.y, 16));
                            finalPubKey = oAuthPubKeyPoint.add(noncePoint);
                        }
                        pubNonce = nonceResult.pubNonce;
                    }

                    String oAuthKeyAddress = KeyUtils.generateAddressFromPrivKey(privateKey.toString(16));
                    String finalEvmAddress = "";
                    if (finalPubKey != null) {
                        finalEvmAddress = KeyUtils.generateAddressFromPubKey(finalPubKey.normalize().getAffineXCoord().toBigInteger().toString(16), finalPubKey.normalize().getAffineYCoord().toBigInteger().toString(16));
                    }

                    String finalPrivKey = "";
                    if (typeOfUser.equals(TypeOfUser.v1) || (typeOfUser.equals(TypeOfUser.v2) && metadataNonce.compareTo(BigInteger.ZERO) > 0)) {
                        BigInteger privateKeyWithNonce = privateKey.add(metadataNonce).mod(secp256k1N);
                        finalPrivKey = Utils.padLeft(privateKeyWithNonce.toString(16), '0', 64);
                    }

                    List<SessionToken> sessionTokens = new ArrayList<>();
                    sessionTokens.addAll(sessionTokenData);
                    Boolean isUpgraded = false;
                    if (typeOfUser.equals(TypeOfUser.v1)) {
                        isUpgraded = false;
                    } else if (typeOfUser.equals(TypeOfUser.v2)) {
                        isUpgraded = metadataNonce.equals(BigInteger.ZERO);
                    }

                    return CompletableFuture.completedFuture(new TorusKey(new FinalKeyData(finalEvmAddress,
                            finalPubKey != null ? finalPubKey.normalize().getAffineXCoord().toString() : null,
                            finalPubKey != null ? finalPubKey.normalize().getAffineYCoord().toString() : null,
                            finalPrivKey),
                            new OAuthKeyData(oAuthKeyAddress, oAuthPubkeyX, oAuthPubkeyY, privateKey.toString(16)),
                            new SessionData(sessionTokens, Hex.toHexString(KeyUtils.serializePrivateKey(sessionAuthKey.getPrivate()))),
                            new Metadata(pubNonce, metadataNonce, typeOfUser, isUpgraded, serverTimeOffsetResponse),
                            new NodesData(nodeIndexes)
                    ));

                } catch (Exception ex) {
                    CompletableFuture<TorusKey> cfRes = new CompletableFuture<>();
                    cfRes.completeExceptionally(new TorusException("Torus Internal Error", ex));
                    return cfRes;
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            CompletableFuture<TorusKey> cfRes = new CompletableFuture<>();
            cfRes.completeExceptionally(new TorusException("Torus Internal Error", e));
            return cfRes;
        }*/
        return null;
    }

    public CompletableFuture<TorusKey> retrieveShares(String[] endpoints, String verifier, VerifierParams verifierParams, String idToken, @Nullable ImportedShare[] importedShares, TorusUtilsExtraParams extraParams) {
        return TorusUtils.retrieveOrImportShare(this.defaultHost, this.options.serverTimeOffset, this.options.enableOneKey, this.defaultHost, this.options.network, this.options.clientId,endpoints, verifier, verifierParams, idToken, importedShares, this.apiKey, extraParams);
    }

    public CompletableFuture<TorusKey> retrieveShares(String[] endpoints, String verifier, VerifierParams verifierParams, String idToken, TorusUtilsExtraParams extraParams) {
        if (extraParams.session_token_exp_second == null) {
            extraParams.session_token_exp_second = this.sessionTime;
        }

        return TorusUtils.retrieveOrImportShare(this.defaultHost, this.options.serverTimeOffset, this.options.enableOneKey, this.defaultHost, this.options.network, this.options.clientId,endpoints, verifier, verifierParams, idToken, new ImportedShare[]{}, this.apiKey, extraParams);
    }

    public static BigInteger getMetadata(String legacyMetadataHost, GetMetadataParams data) throws ExecutionException, InterruptedException {
            Gson gson = new Gson();
            String metadata = gson.toJson(data, GetMetadataParams.class);
            String metadataApiResponse = APIUtils.post(legacyMetadataHost + "/get", metadata, true).get();
            MetadataResponse response = gson.fromJson(metadataApiResponse, MetadataResponse.class);
            return new BigInteger(Utils.isEmpty(response.getMessage()) ? "0" : response.getMessage(), 16);
    }

    public TorusPublicKey getNewPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId, Web3AuthNetwork network) throws Exception {
        KeyLookupResult keyAssignResult = Utils.getPubKeyOrKeyAssign(endpoints, network, verifier, verifierId, this.defaultHost, this.options.serverTimeOffset, extendedVerifierId);

        JsonRPCRequest.JRPCResponse.ErrorInfo errorResult = keyAssignResult.errorResult;
        if (errorResult != null) {
            if (errorResult.getMessage().toLowerCase().contains("verifier not supported")) {
                throw new RuntimeException("Verifier not supported. Check if you:\n1. Are on the right network (Torus testnet/mainnet)\n2. Have setup a verifier on dashboard.web3auth.io?");
            } else {
                throw new RuntimeException(errorResult.getMessage());
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
        if (nonceResult != null && !nonceResult.nonce.isEmpty()) {
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
                ArrayList<LegacyVerifierKey>  legacyKeys = new ArrayList<>();
                for (VerifierKey i : keyAssignResult.keyResult.keys) {
                    legacyKeys.add(new LegacyVerifierKey(i.pub_key_X,i.pub_key_Y,i.address));
                }
                LegacyVerifierLookupResponse verifierLegacyLookupItem =
                        new LegacyVerifierLookupResponse(legacyKeys.toArray(new LegacyVerifierKey[0]), finalServerTimeOffset.toString());
                return formatLegacyPublicKeyData(verifierLegacyLookupItem, true, keyAssignResult.keyResult.is_new_key, finalServerTimeOffset);
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

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(oAuthPubKeyX,  oAuthPubKeyY);
        String finalAddresss = KeyUtils.generateAddressFromPubKey(finalPubKeyX, finalPubKeyY);

        TorusPublicKey key = new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, oAuthPubKeyX, oAuthPubKeyY),
                new FinalPubKeyData(finalAddresss, finalPubKeyX, finalPubKeyY),
                new Metadata(pubNonce, nonce, TypeOfUser.v2, nonceResult != null && nonceResult.upgraded, finalServerTimeOffset),
                new NodesData(keyAssignResult.nodeIndexes));
        return key;
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

        String oAuthPubKey = KeyUtils.getPublicKeyFromCoords(X,Y,true);
        Integer finalServerTimeOffset = (this.options.serverTimeOffset == null) ? serverTimeOffset : this.options.serverTimeOffset;

        if (enableOneKey) {
            nonceResult = Utils.getOrSetNonce(this.defaultHost, X, Y, finalServerTimeOffset, null, !isNewKey, null);
            nonce = (nonceResult.nonce == null) ? BigInteger.ZERO : new BigInteger(nonceResult.nonce);
            typeOfUser = (nonceResult.typeOfUser == null) ? TypeOfUser.v1 : nonceResult.typeOfUser;

            if (typeOfUser == TypeOfUser.v1) {
                finalPubKey = oAuthPubKey;
                nonce = getMetadata(this.defaultHost, new GetMetadataParams(X, Y));

                if (nonce.compareTo(BigInteger.ZERO) > 0) {
                    PrivateKey noncePrivate = KeyUtils.deserializePrivateKey(Hex.decode(Utils.padLeft(nonce.toString(16), '0', 64)));
                    String noncePublicKey = Hex.toHexString(KeyUtils.serializePublicKey(KeyUtils.privateToPublic(noncePrivate), false));
                    finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
                }
            } else if (typeOfUser == TypeOfUser.v2) {
                String pubNonceKey = KeyUtils.getPublicKeyFromCoords(nonceResult.pubNonce.x, nonceResult.pubNonce.y, true);
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(oAuthPubKey, pubNonceKey), false);
                pubNonce = nonceResult.pubNonce;
            } else {
                throw new RuntimeException("getOrSetNonce should always return typeOfUser.");
            }
        } else {
            typeOfUser = TypeOfUser.v1;
            finalPubKey = oAuthPubKey;
            nonce = getMetadata(this.defaultHost, new GetMetadataParams(X,Y));
            if (nonce.compareTo(BigInteger.ZERO) > 0) {
                PrivateKey noncePrivate = KeyUtils.deserializePrivateKey(Hex.decode(Utils.padLeft(nonce.toString(16), '0', 64)));
                String noncePublicKey = Hex.toHexString(KeyUtils.serializePublicKey(KeyUtils.privateToPublic(noncePrivate), false));
                finalPubKey = KeyUtils.combinePublicKeysFromStrings(Arrays.asList(finalPubKey, noncePublicKey), false);
            }
        }

        String oAuthAddress = KeyUtils.generateAddressFromPubKey(X, Y);

        if (typeOfUser == TypeOfUser.v2 && finalPubKey == null) {
            throw TorusUtilError.PRIVATE_KEY_DERIVE_FAILED;
        }

        String[] finalPubKeyCoords = KeyUtils.getPublicKeyCoords(finalPubKey);
        String finalAddress = KeyUtils.generateAddressFromPubKey(finalPubKeyCoords[0],finalPubKeyCoords[1]);

        return new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, Utils.padLeft(X, '0', 64),  Utils.padLeft(Y, '0', 64)),
                new FinalPubKeyData(finalAddress,finalPubKeyCoords[0], finalPubKeyCoords[1]),
                new Metadata(pubNonce, nonce, typeOfUser, (nonceResult != null && nonceResult.upgraded != null) ? nonceResult.upgraded : false, serverTimeOffset),
                new NodesData(new ArrayList<>()));
    }

    public TorusPublicKey getPublicAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo());
    }

    private String getMigratedNetworkInfo() {
        return this.options.network.toString();
    }

    private Web3AuthNetwork getNetworkInfo() {
        return this.options.network;
    }

    public TorusPublicKey getUserTypeAndAddress(@NotNull String[] endpoints, @NotNull String verifier, @NotNull String verifierId, @Nullable String extendedVerifierId) throws Exception {
        return getNewPublicAddress(endpoints, verifier, verifierId, extendedVerifierId, getNetworkInfo());
    }

    public static MetadataParams generateMetadataParams(String message, BigInteger privateKey, Integer serverTimeOffset) {
        BigInteger timeMillis = BigInteger.valueOf(System.currentTimeMillis() / 1000L);
        BigInteger timestamp = (serverTimeOffset.equals(0)) ? timeMillis.add(BigInteger.valueOf(serverTimeOffset)) : BigInteger.valueOf(serverTimeOffset);
        SetData setData = new SetData(message, timestamp.toString(16));
        ECKeyPair derivedECKeyPair = ECKeyPair.create(privateKey);

        String derivedPubKeyString = derivedECKeyPair.getPublicKey().toString(16);
        String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2);
        String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);

        Gson gson = new Gson();
        String setDataString = gson.toJson(setData);
        byte[] hashedData = Hash.sha3(setDataString.getBytes(StandardCharsets.UTF_8));
        ECDSASignature signature = derivedECKeyPair.sign(hashedData);
        String sig = Utils.padLeft(signature.r.toString(16), '0', 64) + Utils.padLeft(signature.s.toString(16), '0', 64) + Utils.padLeft("", '0', 2);
        byte[] sigBytes = Utils.toByteArray(new BigInteger(sig, 16));
        // TODO: Consider java.util.Base64.getEncoder().encode(sigBytes); and remove Base64 class if fine
        String finalSig = new String(Base64.encodeBytesToBytes(sigBytes), StandardCharsets.UTF_8);
        return new MetadataParams(derivedPubKeyX, derivedPubKeyY, setData, finalSig, null, null);
    }


    public CompletableFuture<TorusKey> importPrivateKey(
            String[] endpoints,
            BigInteger[] nodeIndexes,
            TorusNodePub[] nodePubKeys,
            String verifier,
            VerifierParams verifierParams,
            String idToken,
            String newPrivateKey,
            TorusUtilsExtraParams extraParams
    ) throws Exception {

        if (endpoints.length != nodeIndexes.length) {
            CompletableFuture<TorusKey> future = new CompletableFuture<>();
            future.completeExceptionally(new TorusUtilError("Length of endpoints must be the same as length of nodeIndexes"));
            return future;
        }

        if (extraParams.session_token_exp_second == null) {
            extraParams.session_token_exp_second = sessionTime;
        }

        List<ImportedShare> shares = KeyUtils.generateShares(this.keyType, options.serverTimeOffset, Arrays.asList(nodeIndexes), Arrays.asList(nodePubKeys), newPrivateKey);

        return this.retrieveShares(
                endpoints,
                verifier,
                verifierParams,
                idToken,
                shares.toArray(new ImportedShare[0]), extraParams);
    }
}
