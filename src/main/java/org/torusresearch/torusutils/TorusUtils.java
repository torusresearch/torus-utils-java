package org.torusresearch.torusutils;

import static org.torusresearch.fetchnodedetails.types.Utils.LEGACY_NETWORKS_ROUTE_MAP;
import static org.torusresearch.torusutils.helpers.KeyUtils.generateShares;
import static org.torusresearch.torusutils.helpers.Utils.getRandomBytes;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.json.JSONObject;
import org.torusresearch.fetchnodedetails.types.LegacyNetworkMigrationInfo;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.CommitmentRequestParams;
import org.torusresearch.torusutils.apis.Ecies;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.KeyAssignResult;
import org.torusresearch.torusutils.apis.KeyAssignment;
import org.torusresearch.torusutils.apis.NodeSignature;
import org.torusresearch.torusutils.apis.PubKey;
import org.torusresearch.torusutils.apis.ShareRequestParams;
import org.torusresearch.torusutils.apis.VerifierLookupItem;
import org.torusresearch.torusutils.apis.VerifierLookupRequestResult;
import org.torusresearch.torusutils.helpers.AES256CBC;
import org.torusresearch.torusutils.helpers.Base64;
import org.torusresearch.torusutils.helpers.PredicateFailedException;
import org.torusresearch.torusutils.helpers.Some;
import org.torusresearch.torusutils.helpers.Utils;
import org.torusresearch.torusutils.types.DecryptedShare;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.GetOrSetNonceError;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.ImportedShare;
import org.torusresearch.torusutils.types.KeyType;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.MetadataParams;
import org.torusresearch.torusutils.types.MetadataPubKey;
import org.torusresearch.torusutils.types.MetadataResponse;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.PrivateKeyWithNonceResult;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.SessionToken;
import org.torusresearch.torusutils.types.TorusCtorOptions;
import org.torusresearch.torusutils.types.TorusException;
import org.torusresearch.torusutils.types.TorusKey;
import org.torusresearch.torusutils.types.TorusPublicKey;
import org.torusresearch.torusutils.types.TypeOfUser;
import org.torusresearch.torusutils.types.VerifierArgs;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import io.reactivex.annotations.Nullable;
import okhttp3.internal.http2.Header;

public class TorusUtils {

    public final TorusCtorOptions options;
    private static int sessionTime = 86400;
    private KeyType keyType = KeyType.secp256k1;
    public static final BigInteger secp256k1N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");

    {
        setupBouncyCastle();
    }

    public TorusUtils(TorusCtorOptions options) {
        this.options = options;
        this.keyType = options.getKeyType();
    }

    public static void setAPIKey(String apiKey) {
        APIUtils.setApiKey(apiKey);
    }

    public static boolean isGetOrSetNonceError(Exception err) {
        return err instanceof GetOrSetNonceError;
    }

    public static void setSessionTime(int _sessionTime) {
        sessionTime = _sessionTime;
    }

    BigInteger lagrangeInterpolation(BigInteger[] shares, BigInteger[] nodeIndex) {
        if (shares.length != nodeIndex.length) {
            return null;
        }
        BigInteger secret = new BigInteger("0");
        for (int i = 0; i < shares.length; i++) {
            BigInteger upper = new BigInteger("1");
            BigInteger lower = new BigInteger("1");
            for (int j = 0; j < shares.length; j++) {
                if (i != j) {
                    upper = upper.multiply(nodeIndex[j].negate());
                    upper = upper.mod(secp256k1N);
                    BigInteger temp = nodeIndex[i].subtract(nodeIndex[j]);
                    temp = temp.mod(secp256k1N);
                    lower = lower.multiply(temp).mod(secp256k1N);
                }
            }
            BigInteger delta = upper.multiply(lower.modInverse(secp256k1N)).mod(secp256k1N);
            delta = delta.multiply(shares[i]).mod(secp256k1N);
            secret = secret.add(delta);
        }
        return secret.mod(secp256k1N);
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

    private boolean isLegacyNetwork() {
        LegacyNetworkMigrationInfo legacyNetworkMigrationInfo = LEGACY_NETWORKS_ROUTE_MAP.getOrDefault(this.options.getNetwork().toString(), null);
        return legacyNetworkMigrationInfo != null && !legacyNetworkMigrationInfo.getMigrationCompleted();
    }

    public static String getPostboxKey(TorusKey torusKey) {
        if (torusKey.metadata.typeOfUser == TypeOfUser.v1) {
            return (torusKey.finalKeyData.privKey == null || torusKey.finalKeyData.privKey.isEmpty()) ?  torusKey.oAuthKeyData.privKey : torusKey.finalKeyData.privKey;
        }
        return torusKey.oAuthKeyData.privKey;
    }

    public CompletableFuture<TorusKey> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams,
                                                      String idToken, TorusNodePub[] nodePubkeys, HashMap<String, Object> extraParams, String networkMigrated,
                                                      boolean useDkg, @Nullable ImportedShare[] importedShares) {
        try {
            if (nodePubkeys.length == 0) {
                throw new IllegalArgumentException("nodePubkeys param is required");
            }

            if (nodePubkeys.length != indexes.length) {
                throw new IllegalArgumentException("nodePubkeys length must be same as indexes length");
            }

            if (nodePubkeys.length != endpoints.length) {
                throw new IllegalArgumentException("nodePubkeys length must be same as endpoints length");
            }

            // dkg is used by default only for secp256k1 keys,
            // for ed25519 keys import keys flows is the default
            boolean shouldUseDkg = useDkg;
            shouldUseDkg = this.keyType != KeyType.ed25519;

            if (!shouldUseDkg && (nodePubkeys.length == 0)) {
                throw new IllegalArgumentException("nodePubkeys param is required");
            }

            APIUtils.get(this.options.getAllowHost(), new Header[]{new Header("Origin", this.options.getOrigin()), new Header("verifier", verifier), new Header("verifierid", verifierParams.get("verifier_id").toString()), new Header("network", networkMigrated),
                    new Header("clientid", this.options.getClientId()), new Header("enablegating", "true")}, true).get();
            List<CompletableFuture<String>> promiseArr = new ArrayList<>();
            Set<SessionToken> sessionTokenData = new HashSet<>();
            Set<BigInteger> nodeIndexs = new HashSet<>();
            // generate temporary private and public key that is used to secure receive shares
            ECKeyPair sessionAuthKey = Keys.createEcKeyPair();
            String pubKey = Utils.padLeft(sessionAuthKey.getPublicKey().toString(16), '0', 128);
            String pubKeyX = pubKey.substring(0, pubKey.length() / 2);
            String pubKeyY = pubKey.substring(pubKey.length() / 2);

            List<ImportedShare> newImportedShares = new ArrayList<>();
            List<ImportedShare> finalImportedShares = new ArrayList<>();

            if (!newImportedShares.isEmpty()) {
                if (newImportedShares.size() != endpoints.length) {
                    throw new IllegalArgumentException("Invalid imported shares length");
                }
                finalImportedShares.addAll(newImportedShares);
            } else if (!useDkg) {
                byte[] bufferKey;
                if (keyType.equals(KeyType.secp256k1)) {
                    bufferKey = Keys.createEcKeyPair().getPrivateKey().toByteArray();
                } else {
                    bufferKey = getRandomBytes(32);
                }
                List<ImportedShare> generatedShares = generateShares(keyType, this.options.getServerTimeOffset(), Arrays.stream(indexes).toList(), Arrays.stream(nodePubkeys).toList(), Arrays.toString(bufferKey));
                finalImportedShares.addAll(generatedShares);
            }

            String tokenCommitment = org.web3j.crypto.Hash.sha3String(idToken);
            int t = endpoints.length / 4;
            int k = t * 2 + 1;

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
            // send share request once k + t number of commitment requests have completed
            boolean finalIsImportShareReq = isImportShareReq;
            return new Some<>(promiseArr, (resultArr, commitmentsResolved) -> {
                List<String> completedRequests = new ArrayList<>();
                for (String result : resultArr) {
                    if (result != null && !result.isEmpty()) {
                        completedRequests.add(result);
                    }
                }
                CompletableFuture<List<String>> completableFuture = new CompletableFuture<>();
                if (importedShares != null &&  importedShares.length > 0 && completedRequests.size() == endpoints.length) {
                    completableFuture.complete(Arrays.asList(resultArr));
                } else if (importedShares != null &&  importedShares.length == 0 && completedRequests.size() >= k + t) {
                    Gson gson = new Gson();
                    // we don't consider commitment to succeed unless node 1 responds
                    boolean requiredNodeResultFound = completedRequests.stream().anyMatch(x -> {
                        if (x == null || x.isEmpty()) return false;
                        JsonRPCResponse nodeSigResponse = gson.fromJson(x, JsonRPCResponse.class);
                        if (nodeSigResponse == null || nodeSigResponse.getResult() == null) return false;
                        NodeSignature nodeSignature = gson.fromJson(Utils.convertToJsonObject(nodeSigResponse.getResult()), NodeSignature.class);
                        return nodeSignature != null && nodeSignature.getNodeindex().equals("1");
                    });
                    if (requiredNodeResultFound) completableFuture.complete(completedRequests);
                    else completableFuture.completeExceptionally(new PredicateFailedException("commitment from node 1 not found"));
                } else {
                    completableFuture.completeExceptionally(new PredicateFailedException("insufficient responses for commitments"));
                }
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
                    NodeSignature[] nodeSignatures = new NodeSignature[nodeSigs.size()];
                    for (int l = 0; l < nodeSigs.size(); l++) {
                        Gson gson = new Gson();
                        nodeSignatures[l] = gson.fromJson(nodeSigs.get(l), NodeSignature.class);
                    }
                    verifierParams.put("idtoken", idToken);
                    verifierParams.put("nodesignatures", nodeSignatures);
                    verifierParams.put("verifieridentifier", verifier);
                    if (extraParams != null) {
                        extraParams.put("session_token_exp_second", sessionTime);
                        verifierParams.putAll(extraParams);
                    }
                    for (int i = 0; i < endpoints.length; i++) {
                        String req;
                        List<HashMap<String, Object>> shareRequestItems = new ArrayList<>();
                        if (finalIsImportShareReq) {
                            verifierParams.put("pub_key_x", importedShares[i].getOauth_pub_key_x());
                            verifierParams.put("pub_key_y", importedShares[i].getOauth_pub_key_y());
                            verifierParams.put("encrypted_share", importedShares[i].getEncryptedShare());
                            verifierParams.put("encrypted_share_metadata", importedShares[i].getEncryptedShareMetadata());
                            verifierParams.put("node_index", importedShares[i].getNode_index());
                            verifierParams.put("key_type", importedShares[i].getKey_type());
                            verifierParams.put("nonce_data", importedShares[i].getNonce_data());
                            verifierParams.put("nonce_signature", importedShares[i].getNonce_signature());
                            shareRequestItems.add(verifierParams);
                            req = APIUtils.generateJsonRPCObject("ImportShare", new ShareRequestParams(shareRequestItems));
                        } else {
                            shareRequestItems.add(verifierParams);
                            req = APIUtils.generateJsonRPCObject(Utils.getJsonRPCObjectMethodName(networkMigrated), new ShareRequestParams(shareRequestItems));
                        }
                        promiseArrRequests.add(APIUtils.post(endpoints[i], req, true));
                    }
                    return new Some<>(promiseArrRequests, (shareResponses, predicateResolved) -> {
                        try {
                            // check if threshold number of nodes have returned the same user public key
                            BigInteger privateKey = null;
                            List<String> completedResponses = new ArrayList<>();
                            Gson gson = new Gson();
                            for (String shareResponse : shareResponses) {
                                if (shareResponse != null && !shareResponse.equals("")) {
                                    try {
                                        JsonRPCResponse shareResponseJson = gson.fromJson(shareResponse, JsonRPCResponse.class);
                                        if (shareResponseJson != null && shareResponseJson.getResult() != null) {
                                            completedResponses.add(Utils.convertToJsonObject(shareResponseJson.getResult()));
                                        }
                                    } catch (JsonSyntaxException e) {
                                        // discard this, we don't care
                                    }
                                }
                            }
                            List<String> completedResponsesPubKeys = new ArrayList<>();
                            GetOrSetNonceResult thresholdNonceData = null;
                            ArrayList<String> isNewKeyArr = new ArrayList<>();
                            for (String x : completedResponses) {
                                KeyAssignResult keyAssignResult = gson.fromJson(x, KeyAssignResult.class);
                                if (keyAssignResult == null || keyAssignResult.getKeys() == null || keyAssignResult.getKeys().length == 0) {
                                    return null;
                                }
                                KeyAssignment keyAssignResultFirstKey = keyAssignResult.getKeys()[0];
                                completedResponsesPubKeys.add(Utils.convertToJsonObject(keyAssignResultFirstKey.getPublicKey(networkMigrated)));
                                if (Utils.isSapphireNetwork(networkMigrated)) {
                                    GetOrSetNonceResult.PubNonce pubNonce = keyAssignResultFirstKey.getNonceData().getPubNonce();
                                    if (pubNonce != null && pubNonce.getX() != null) {
                                        thresholdNonceData = keyAssignResult.getKeys()[0].getNonceData();
                                    }
                                }
                            }
                            String thresholdPublicKeyString = Utils.thresholdSame(completedResponsesPubKeys, k);
                            PubKey thresholdPubKey = null;

                            if (thresholdPublicKeyString == null) {
                                throw new RuntimeException("Invalid result from nodes, threshold number of public key results are not matching");
                            }

                            // If both thresholdNonceData and extended_verifier_id are not available,
                            // then we need to throw an error; otherwise, the address would be incorrect.
                            if (thresholdNonceData == null && verifierParams.get("extended_verifier_id") == null &&
                                    !LEGACY_NETWORKS_ROUTE_MAP.containsKey(networkMigrated)) {
                                throw new RuntimeException(String.format(
                                        "Invalid metadata result from nodes, nonce metadata is empty for verifier: %s and verifierId: %s",
                                        verifier, verifierParams.get("verifier_id"))
                                );
                            }

                            if (!thresholdPublicKeyString.isEmpty()) {
                                thresholdPubKey = gson.fromJson(thresholdPublicKeyString, PubKey.class);
                            }
                            if (completedResponses.size() >= k && thresholdPubKey != null && (thresholdNonceData != null || verifierParams.get("extended_verifier_id") != null ||
                                    LEGACY_NETWORKS_ROUTE_MAP.containsKey(networkMigrated))) {
                                List<DecryptedShare> decryptedShares = new ArrayList<>();
                                List<CompletableFuture<byte[]>> sharePromises = new ArrayList<>();
                                List<CompletableFuture<byte[]>> sessionTokenSigPromises = new ArrayList<>();
                                List<CompletableFuture<byte[]>> sessionTokenPromises = new ArrayList<>();
                                List<BigInteger> serverTimeOffsetResponses = new ArrayList<>();
                                KeyAssignResult currentShareResponse = null;

                                for (int i = 0; i < shareResponses.length; i++) {
                                    if (shareResponses[i] != null && !shareResponses[i].isEmpty()) {
                                        try {
                                            JsonRPCResponse currentJsonRPCResponse = gson.fromJson(shareResponses[i], JsonRPCResponse.class);
                                            if (currentJsonRPCResponse != null && currentJsonRPCResponse.getResult() != null && !currentJsonRPCResponse.getResult().equals("")) {
                                                currentShareResponse = gson.fromJson(Utils.convertToJsonObject(currentJsonRPCResponse.getResult()), KeyAssignResult.class);
                                                isNewKeyArr.add(currentShareResponse.getIsNewKey());
                                                serverTimeOffsetResponses.add(currentShareResponse.getServerTimeOffset() != null ? new BigInteger(currentShareResponse.getServerTimeOffset()) : BigInteger.ZERO);
                                                if (currentShareResponse.getSessionTokenSigs() != null && currentShareResponse.getSessionTokenSigs().length > 0) {
                                                    // Decrypt sessionSig if enc metadata is sent
                                                    Ecies[] sessionTokenSigMetaData = currentShareResponse.getSessionTokenSigMetadata();
                                                    if (sessionTokenSigMetaData != null && sessionTokenSigMetaData[0] != null && sessionTokenSigMetaData[0].getEphemPublicKey() != null) {
                                                        try {
                                                            AES256CBC aes256cbc = new AES256CBC(sessionAuthKey.getPrivateKey().toString(16), sessionTokenSigMetaData[0].getEphemPublicKey(),
                                                                    sessionTokenSigMetaData[0].getIv());
                                                            byte[] encryptedShareBytes = AES256CBC.toByteArray(new BigInteger(currentShareResponse.getSessionTokenSigs()[0], 16));
                                                            sessionTokenSigPromises.add(CompletableFuture.completedFuture(aes256cbc.decrypt(Base64.encodeBytes(encryptedShareBytes))));
                                                        } catch (Exception ex) {
                                                            System.out.println("session token sig decryption" + ex);
                                                            return null;
                                                        }
                                                    } else {
                                                        sessionTokenSigPromises.add(CompletableFuture.completedFuture(currentShareResponse.getSessionTokenSigs()[0].getBytes(StandardCharsets.UTF_8)));
                                                    }
                                                } else {
                                                    sessionTokenSigPromises.add(CompletableFuture.completedFuture(null));
                                                }

                                                if (currentShareResponse.getSessionTokens() != null && currentShareResponse.getSessionTokens().length > 0) {
                                                    // Decrypt sessionToken if enc metadata is sent
                                                    Ecies[] sessionTokenMetaData = currentShareResponse.getSessionTokenMetadata();
                                                    if (sessionTokenMetaData != null && sessionTokenMetaData[0] != null &&
                                                            currentShareResponse.getSessionTokenMetadata()[0].getEphemPublicKey() != null) {
                                                        try {
                                                            AES256CBC aes256cbc = new AES256CBC(sessionAuthKey.getPrivateKey().toString(16), sessionTokenMetaData[0].getEphemPublicKey(),
                                                                    sessionTokenMetaData[0].getIv());
                                                            byte[] encryptedShareBytes = AES256CBC.toByteArray(new BigInteger(currentShareResponse.getSessionTokens()[0], 16));
                                                            sessionTokenPromises.add(CompletableFuture.completedFuture(aes256cbc.decrypt(Base64.encodeBytes(encryptedShareBytes))));
                                                        } catch (Exception ex) {
                                                            System.out.println("share decryption" + ex);
                                                            return null;
                                                        }
                                                    } else {
                                                        sessionTokenPromises.add(CompletableFuture.completedFuture(currentShareResponse.getSessionTokens()[0].getBytes(StandardCharsets.UTF_8)));
                                                    }
                                                } else {
                                                    sessionTokenSigPromises.add(CompletableFuture.completedFuture(null));
                                                }

                                                if (currentShareResponse.getKeys() != null && currentShareResponse.getKeys().length > 0) {
                                                    KeyAssignment firstKey = currentShareResponse.getKeys()[0];
                                                    if (firstKey.getNodeIndex() != null) {
                                                        nodeIndexs.add(new BigInteger(firstKey.getNodeIndex()));
                                                    }
                                                    if (firstKey.getMetadata(networkMigrated) != null) {
                                                        try {
                                                            AES256CBC aes256cbc = new AES256CBC(sessionAuthKey.getPrivateKey().toString(16), firstKey.getMetadata(networkMigrated).getEphemPublicKey(), firstKey.getMetadata(networkMigrated).getIv());
                                                            // Implementation specific oddity - hex string actually gets passed as a base64 string
                                                            String hexUTF8AsBase64 = firstKey.getShare(networkMigrated);
                                                            String hexUTF8 = new String(Base64.decode(hexUTF8AsBase64), StandardCharsets.UTF_8);
                                                            byte[] encryptedShareBytes = AES256CBC.toByteArray(new BigInteger(hexUTF8, 16));
                                                            BigInteger share = new BigInteger(1, aes256cbc.decrypt(Base64.encodeBytes(encryptedShareBytes)));
                                                            decryptedShares.add(new DecryptedShare(indexes[i], share));
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

                                List<CompletableFuture<byte[]>> allPromises = new ArrayList<>();
                                allPromises.addAll(sharePromises);
                                allPromises.addAll(sessionTokenSigPromises);
                                allPromises.addAll(sessionTokenPromises);

                                CompletableFuture.allOf(allPromises.toArray(new CompletableFuture[0])).join();

                                List<CompletableFuture<byte[]>> sharesResolved = allPromises.subList(0, sharePromises.size());
                                List<CompletableFuture<byte[]>> sessionSigsResolved = allPromises.subList(sharePromises.size(), sharePromises.size() + sessionTokenSigPromises.size());
                                List<CompletableFuture<byte[]>> sessionTokensResolved = allPromises.subList(sharePromises.size() + sessionTokenSigPromises.size(), allPromises.size());

                                List<CompletableFuture<byte[]>> validSigs = new ArrayList<>();
                                for (CompletableFuture<byte[]> sig : sessionSigsResolved) {
                                    if (sig != null) {
                                        validSigs.add(sig);
                                    }
                                }

                                int minThresholdRequired = (int) Math.floor(endpoints.length / 2) + 1;
                                if (verifierParams.get("extended_verifier_id") != null && validSigs.size() < minThresholdRequired) {
                                    throw new Error("Insufficient number of signatures from nodes, required: " + minThresholdRequired + ", found: " + validSigs.size());
                                }

                                List<CompletableFuture<byte[]>> validTokens = new ArrayList<>();
                                for (CompletableFuture<byte[]> token : sessionTokensResolved) {
                                    if (token != null) {
                                        validTokens.add(token);
                                    }
                                }

                                if (verifierParams.get("extended_verifier_id") != null && validTokens.size() < minThresholdRequired) {
                                    throw new Error("Insufficient number of session tokens from nodes, required: " + minThresholdRequired + ", found: " + validTokens.size());
                                }

                                for (int index = 0; index < sessionTokensResolved.size(); index++) {
                                    if (sessionSigsResolved.get(index) == null) {
                                        sessionTokenData.add(null);
                                    } else {
                                        JsonRPCResponse jsonRPCResponse = gson.fromJson(shareResponses[index], JsonRPCResponse.class);
                                        KeyAssignResult keyAssignResult = gson.fromJson(Utils.convertToJsonObject(jsonRPCResponse.getResult()), KeyAssignResult.class);
                                        sessionTokenData.add(new SessionToken(Base64.encodeBytes(sessionTokensResolved.get(index).get()),
                                                        Utils.bytesToHex(sessionSigsResolved.get(index).get()),
                                                        keyAssignResult.getNodePubx(),
                                                        keyAssignResult.getNodePuby()
                                                )
                                        );
                                    }
                                }

                                List<BigInteger> serverOffsetTimes = serverTimeOffsetResponses;

                                BigInteger serverTimeOffsetResponse = !Objects.equals(this.options.getServerTimeOffset(), BigInteger.ZERO) ?
                                        this.options.getServerTimeOffset() : Utils.calculateMedian(serverOffsetTimes);

                                if (predicateResolved.get()) return null;

                                List<BigInteger> _nodeIndexs = new ArrayList<>(nodeIndexs);
                                for (int index = 0; index < sharesResolved.size(); index++) {
                                    Object curr = sharesResolved.get(index);
                                    if (curr != null) {
                                        decryptedShares.add(new DecryptedShare(_nodeIndexs.get(index), new BigInteger(curr.toString())));
                                    }
                                }

                                List<List<Integer>> allCombis = Utils.kCombinations(decryptedShares.size(), k);
                                for (List<Integer> currentCombi : allCombis) {
                                    List<BigInteger> currentCombiSharesIndexes = new ArrayList<>();
                                    List<BigInteger> currentCombiSharesValues = new ArrayList<>();
                                    for (int i = 0; i < decryptedShares.size(); i++) {
                                        if (currentCombi.contains(i)) {
                                            DecryptedShare decryptedShare = decryptedShares.get(i);
                                            currentCombiSharesIndexes.add(decryptedShare.getIndex());
                                            currentCombiSharesValues.add(decryptedShare.getValue());
                                        }
                                    }
                                    BigInteger derivedPrivateKey = this.lagrangeInterpolation(currentCombiSharesValues.toArray(new BigInteger[0]), currentCombiSharesIndexes.toArray(new BigInteger[0]));
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
                BigInteger serverTimeOffsetResponse = privateKeyWithNonceResult.getServerTimeOffsetResponse();
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
                        metadataNonce = new BigInteger(Utils.isEmpty(thresholdNonceData.getNonce()) ? "0" : thresholdNonceData.getNonce(), 16);
                    } else {
                        nonceResult = this.getNonce(privateKey, serverTimeOffsetResponse).get();
                        metadataNonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                    }
                    List<BigInteger> nodeIndexes = new ArrayList<>(nodeIndexs);
                    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                    ECPoint finalPubKey = null;
                    GetOrSetNonceResult.PubNonce pubNonce = null;
                    TypeOfUser typeOfUser;
                    if (verifierParams.get("extended_verifier_id") != null && !verifierParams.get("extended_verifier_id").equals("")) {
                        typeOfUser = TypeOfUser.v2;
                        // for tss key no need to add pub nonce
                        finalPubKey = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                    } else if (LEGACY_NETWORKS_ROUTE_MAP.containsKey(networkMigrated)) {
                        if (this.options.isEnableOneKey()) {
                            nonceResult = this.getNonce(privateKey, serverTimeOffsetResponse).get();
                            pubNonce = nonceResult.getPubNonce();
                            metadataNonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                            typeOfUser = nonceResult.getTypeOfUser();
                            if (typeOfUser.equals(TypeOfUser.v2)) {
                                typeOfUser = TypeOfUser.v2;
                                ECPoint oAuthPubKeyPoint = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                                ECPoint pubNoncePoint = curve.getCurve().createPoint(new BigInteger(pubNonce.getX(), 16), new BigInteger(pubNonce.getY(), 16));
                                finalPubKey = oAuthPubKeyPoint.add(pubNoncePoint);
                            } else {
                                typeOfUser = TypeOfUser.v1;
                                metadataNonce = this.getMetadata(new MetadataPubKey(oAuthPubkeyX, oAuthPubkeyY)).get();
                                BigInteger privateKeyWithNonce = privateKey.add(metadataNonce).mod(secp256k1N);
                                finalPubKey = curve.getG().multiply(privateKeyWithNonce).normalize();
                            }
                        } else {
                            typeOfUser = TypeOfUser.v1;
                            metadataNonce = this.getMetadata(new MetadataPubKey(oAuthPubkeyX, oAuthPubkeyY)).get();
                            BigInteger privateKeyWithNonce = privateKey.add(metadataNonce).mod(secp256k1N);
                            finalPubKey = curve.getG().multiply(privateKeyWithNonce).normalize();
                        }
                    } else {
                        typeOfUser = TypeOfUser.v2;
                        ECPoint oAuthPubKeyPoint = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                        if (nonceResult.getPubNonce() != null && nonceResult.getPubNonce().getX().length() > 0 && nonceResult.getPubNonce().getY().length() > 0) {
                            ECPoint noncePoint = curve.getCurve().createPoint(new BigInteger(nonceResult.getPubNonce().getX(), 16), new BigInteger(nonceResult.getPubNonce().getY(), 16));
                            finalPubKey = oAuthPubKeyPoint.add(noncePoint);
                        }
                        pubNonce = nonceResult.getPubNonce();
                    }

                    String oAuthKeyAddress = this.generateAddressFromPrivKey(privateKey.toString(16));
                    String finalEvmAddress = "";
                    if (finalPubKey != null) {
                        finalEvmAddress = generateAddressFromPubKey(finalPubKey.normalize().getAffineXCoord().toBigInteger(), finalPubKey.normalize().getAffineYCoord().toBigInteger());
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
                            new SessionData(sessionTokens, sessionAuthKey.getPrivateKey().toString(16)),
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
        }
    }

    public CompletableFuture<TorusKey> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams, String idToken, TorusNodePub[] nodePubkeys, @Nullable ImportedShare[] importedShares) {
        return this.retrieveShares(endpoints, indexes, verifier, verifierParams, idToken, nodePubkeys, null, getMigratedNetworkInfo(), false, importedShares);
    }

    public CompletableFuture<TorusKey> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams, String idToken, TorusNodePub[] nodePubkeys) {
        return this.retrieveShares(endpoints, indexes, verifier, verifierParams, idToken, nodePubkeys, null, getMigratedNetworkInfo(), false, new ImportedShare[]{});
    }

    public CompletableFuture<BigInteger> getMetadata(MetadataPubKey data) {
        try {
            Gson gson = new Gson();
            String metadata = gson.toJson(data, MetadataPubKey.class);
            String metadataApiResponse = APIUtils.post(this.options.getLegacyMetadataHost() + "/get", metadata, true).get();
            MetadataResponse response = gson.fromJson(metadataApiResponse, MetadataResponse.class);
            BigInteger finalResponse = new BigInteger(Utils.isEmpty(response.getMessage()) ? "0" : response.getMessage(), 16);
            return CompletableFuture.supplyAsync(() -> finalResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return CompletableFuture.supplyAsync(() -> new BigInteger("0"));
        }
    }

    public String generateAddressFromPrivKey(String privateKey) {
        BigInteger privKey = new BigInteger(privateKey, 16);
        return Keys.toChecksumAddress(Keys.getAddress(ECKeyPair.create(privKey.toByteArray())));
    }

    public String generateAddressFromPubKey(BigInteger pubKeyX, BigInteger pubKeyY) {
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint rawPoint = curve.getCurve().createPoint(pubKeyX, pubKeyY);
        String finalPubKey = Utils.padLeft(rawPoint.getAffineXCoord().toString(), '0', 64) + Utils.padLeft(rawPoint.getAffineYCoord().toString(), '0', 64);
        return Keys.toChecksumAddress(Hash.sha3(finalPubKey).substring(64 - 38));
    }

    public CompletableFuture<TorusPublicKey> getNewPublicAddress(String[] endpoints, VerifierArgs verifierArgs, boolean isExtended, String networkMigrated) {
        System.out.println("> torusUtils.java/getPublicAddress " + endpoints + " " + verifierArgs + " " + isExtended);
        AtomicBoolean isNewKey = new AtomicBoolean(false);
        Gson gson = new Gson();
        return Utils.getPubKeyOrKeyAssign(endpoints, networkMigrated, verifierArgs.getVerifier(), verifierArgs.getVerifierId(), this.keyType, verifierArgs.getExtendedVerifierId())
                .thenComposeAsync(keyAssignResult -> {
                    String errorResult = keyAssignResult.getErrResult();
                    String keyResult = keyAssignResult.getKeyResult();
                    List<BigInteger> nodeIndexes = keyAssignResult.getNodeIndexes();
                    GetOrSetNonceResult nonceResult = keyAssignResult.getNonceResult();
                    BigInteger finalServerTimeOffset = (keyAssignResult.getServerTimeOffset() != null) ? keyAssignResult.getServerTimeOffset() : this.options.getServerTimeOffset();

                    if (errorResult != null && errorResult.toLowerCase().contains("verifier not supported")) {
                        throw new RuntimeException("Verifier not supported. Check if you:\n1. Are on the right network (Torus testnet/mainnet)\n2. Have setup a verifier on dashboard.web3auth.io?");
                    }

                    if (errorResult != null && errorResult.length() > 0) {
                        throw new RuntimeException("node results do not match at first lookup " + keyResult + ", " + errorResult);
                    }

                    System.out.println("> torusUtils.java/getPublicAddress " + keyResult);
                    VerifierLookupRequestResult verifierLookupRequestResult = gson.fromJson(keyAssignResult.getKeyResult(), VerifierLookupRequestResult.class);
                    if (verifierLookupRequestResult == null || verifierLookupRequestResult.getKeys() == null) {
                        throw new RuntimeException("node results do not match at final lookup " + keyResult + ", " + errorResult);
                    }

                    if (nonceResult == null && verifierArgs.getExtendedVerifierId() == null &&
                            !LEGACY_NETWORKS_ROUTE_MAP.containsKey(networkMigrated)) {
                        try {
                            throw new GetOrSetNonceError(new Exception("metadata nonce is missing in share response"));
                        } catch (GetOrSetNonceError e) {
                            e.printStackTrace();
                        }
                    }

                    VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                    isNewKey.set(true);
                    String X = verifierLookupItem.getPub_key_X();
                    String Y = verifierLookupItem.getPub_key_Y();
                    TypeOfUser typeOfUser = TypeOfUser.v1;
                    GetOrSetNonceResult.PubNonce pubNonce = null;
                    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                    BigInteger nonce = new BigInteger("0");
                    try {
                        nonce = new BigInteger(nonceResult != null ? nonceResult.getNonce() : "0", 16);
                    } catch (Exception exception) {
                        // do nothing
                    }
                    CompletableFuture<TorusPublicKey> keyCf = new CompletableFuture<>();

                    ECPoint oAuthPubKey = null;
                    ECPoint finalPubKey = null;

                    if (verifierArgs.getExtendedVerifierId() != null && !verifierArgs.getExtendedVerifierId().equals("")) {
                        finalPubKey = Utils.getPublicKeyFromHex(X, Y);
                        oAuthPubKey = finalPubKey;
                    } else if (LEGACY_NETWORKS_ROUTE_MAP.containsKey(networkMigrated)) {
                        try {
                            return formatLegacyPublicKeyData(verifierLookupItem, true, isNewKey, finalServerTimeOffset);
                        } catch (GetOrSetNonceError | ExecutionException | InterruptedException e) {
                            e.printStackTrace();
                        }
                    } else {
                        oAuthPubKey = Utils.getPublicKeyFromHex(X, Y);
                        finalPubKey = curve.getCurve().createPoint(new BigInteger(X, 16), new BigInteger(Y, 16));
                        finalPubKey = finalPubKey.add(curve.getG().multiply(nonce)).normalize();
                        pubNonce = nonceResult.getPubNonce();
                    }

                    if (oAuthPubKey == null) {
                        throw new Error("Unable to derive oAuthPubKey");
                    }
                    String oAuthX = oAuthPubKey.getAffineXCoord().toString();
                    String oAuthY = oAuthPubKey.getAffineYCoord().toString();
                    String oAuthAddress = generateAddressFromPubKey(oAuthPubKey.getAffineXCoord().toBigInteger(), oAuthPubKey.getAffineYCoord().toBigInteger());
                    if (finalPubKey == null) {
                        throw new Error("Unable to derive finalPubKey");
                    }
                    String finalX = finalPubKey != null ? finalPubKey.getXCoord().toString() : "";
                    String finalY = finalPubKey != null ? finalPubKey.getYCoord().toString() : "";
                    String finalAddress = finalPubKey != null ? generateAddressFromPubKey(finalPubKey.getXCoord().toBigInteger(), finalPubKey.getYCoord().toBigInteger()) : "";

                    TorusPublicKey key = new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, oAuthX, oAuthY),
                            new FinalPubKeyData(finalAddress, finalX, finalY),
                            new Metadata(pubNonce, nonce, TypeOfUser.v2, nonceResult != null && nonceResult.isUpgraded(), finalServerTimeOffset),
                            new NodesData(nodeIndexes));
                    keyCf.complete(key);
                    return keyCf;
                });
    }

    private CompletableFuture<TorusPublicKey> formatLegacyPublicKeyData(VerifierLookupItem finalKeyResult, boolean enableOneKey, AtomicBoolean isNewKey,
                                                                        BigInteger serverTimeOffset) throws GetOrSetNonceError, ExecutionException, InterruptedException {
        String X = finalKeyResult.getPub_key_X();
        String Y = finalKeyResult.getPub_key_Y();

        CompletableFuture<TorusPublicKey> keyCf = new CompletableFuture<>();
        GetOrSetNonceResult nonceResult = null;
        BigInteger nonce;
        ECPoint finalPubKey;
        TypeOfUser typeOfUser;
        GetOrSetNonceResult.PubNonce pubNonce = null;
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint oAuthPubKey = Utils.getPublicKeyFromHex(X, Y);

        if (enableOneKey) {
            try {
                nonceResult = this.getOrSetNonce(finalKeyResult.getPub_key_X(), finalKeyResult.getPub_key_Y(), false).get();
                nonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                typeOfUser = nonceResult.getTypeOfUser();
            } catch (Exception e) {
                keyCf.completeExceptionally(new GetOrSetNonceError(e));
                return keyCf;
            }

            finalPubKey = curve.getCurve().createPoint(new BigInteger(finalKeyResult.getPub_key_X(), 16), new BigInteger(finalKeyResult.getPub_key_Y(), 16));
            if (nonceResult.getTypeOfUser() == TypeOfUser.v1) {
                finalPubKey = finalPubKey.add(curve.getG().multiply(nonce)).normalize();
            } else if (nonceResult.getTypeOfUser() == TypeOfUser.v2) {
                assert nonceResult.getPubNonce() != null;
                ECPoint oneKeyMetadataPoint = curve.getCurve().createPoint(new BigInteger(nonceResult.getPubNonce().getX(), 16), new BigInteger(nonceResult.getPubNonce().getY(), 16));
                finalPubKey = finalPubKey.add(oneKeyMetadataPoint).normalize();
                pubNonce = nonceResult.getPubNonce();
            } else {
                keyCf.completeExceptionally(new Exception("getOrSetNonce should always return typeOfUser."));
                return keyCf;
            }
        } else {
            typeOfUser = TypeOfUser.v1;
            nonce = this.getMetadata(new MetadataPubKey(X, Y)).get();
            finalPubKey = curve.getCurve().createPoint(new BigInteger(X, 16), new BigInteger(Y, 16));
            finalPubKey = finalPubKey.add(curve.getG().multiply(nonce)).normalize();
        }

        if (oAuthPubKey == null) {
            throw new Error("Unable to derive oAuthPubKey");
        }
        String oAuthX = oAuthPubKey.getAffineXCoord().toString();
        String oAuthY = oAuthPubKey.getAffineYCoord().toString();
        String oAuthAddress = generateAddressFromPubKey(oAuthPubKey.getAffineXCoord().toBigInteger(), oAuthPubKey.getAffineYCoord().toBigInteger());
        if (typeOfUser.equals(TypeOfUser.v2) && finalPubKey == null) {
            throw new Error("Unable to derive finalPubKey");
        }
        String finalX = finalPubKey != null ? finalPubKey.getAffineXCoord().toString() : "";
        String finalY = finalPubKey != null ? finalPubKey.getAffineYCoord().toString() : "";
        String finalAddress = finalPubKey != null ? generateAddressFromPubKey(finalPubKey.getAffineXCoord().toBigInteger(), finalPubKey.getAffineYCoord().toBigInteger()) : "";

        TorusPublicKey key = new TorusPublicKey(new OAuthPubKeyData(oAuthAddress, oAuthX, oAuthY),
                new FinalPubKeyData(finalAddress, finalX, finalY),
                new Metadata(pubNonce, nonce, typeOfUser, nonceResult != null && nonceResult.isUpgraded(), serverTimeOffset),
                new NodesData(new ArrayList<>()));
        keyCf.complete(key);
        return keyCf;
    }

    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, VerifierArgs verifierArgs, boolean isExtended) {
        return getNewPublicAddress(endpoints, verifierArgs, isExtended, getMigratedNetworkInfo());
    }

    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, VerifierArgs verifierArgs) {
        return getNewPublicAddress(endpoints, verifierArgs, false, getMigratedNetworkInfo());
    }

    private String getMigratedNetworkInfo() {
        return this.options.getNetwork().toString();
    }

    private CompletableFuture<GetOrSetNonceResult> _getOrSetNonce(MetadataParams data) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        String finalData = gson.toJson(data);
        CompletableFuture<GetOrSetNonceResult> cf = new CompletableFuture<>();
        APIUtils.post(this.options.getLegacyMetadataHost() + "/get_or_set_nonce", finalData, true).whenCompleteAsync((res, ex) -> {
            if (ex != null) {
                cf.completeExceptionally(ex);
                return;
            }
            try {
                JSONObject jsonObject = new JSONObject(res);
                if (jsonObject.has("ipfs")) {
                    jsonObject.remove("ipfs");
                }
                GetOrSetNonceResult result = gson.fromJson(jsonObject.toString(), GetOrSetNonceResult.class);
                System.out.println("_getOrSetNonce successful!");
                cf.complete(result);
            } catch (Exception ex2) {
                cf.completeExceptionally(ex2);
            }
        });
        return cf;
    }

    public CompletableFuture<GetOrSetNonceResult> getOrSetNonce(String X, String Y, boolean getOnly) {
        String msg = getOnly ? "getNonce" : "getOrSetNonce";
        MetadataParams data = new MetadataParams(X, Y, new MetadataParams.MetadataSetData(msg, null), null, KeyType.secp256k1);
        return this._getOrSetNonce(data);
    }

    public CompletableFuture<GetOrSetNonceResult> getOrSetNonce(BigInteger privKey, BigInteger serverTimeOffset, boolean getOnly) {
        String msg = getOnly ? "getNonce" : "getOrSetNonce";
        MetadataParams data = this.generateMetadataParams(msg, privKey, serverTimeOffset);
        return this._getOrSetNonce(data);
    }

    public CompletableFuture<GetOrSetNonceResult> getNonce(String X, String Y, BigInteger serverTimeOffset) {
        return this.getOrSetNonce(X, Y, true);
    }

    public CompletableFuture<GetOrSetNonceResult> getNonce(BigInteger privKey, BigInteger serverTimeOffset) {
        return this.getOrSetNonce(privKey, serverTimeOffset, true);
    }

    public CompletableFuture<TorusPublicKey> getUserTypeAndAddress(String[] endpoints, VerifierArgs verifierArgs) {
        return getNewPublicAddress(endpoints, verifierArgs, false, getMigratedNetworkInfo());
    }

    public MetadataParams generateMetadataParams(String message, BigInteger privateKey, BigInteger serverTimeOffset) {
        long timeMillis = System.currentTimeMillis() / 1000L;
        BigInteger timestamp = (serverTimeOffset.equals(BigInteger.ZERO)) ? this.options.getServerTimeOffset().add(new BigInteger(String.valueOf(timeMillis))) : serverTimeOffset;
        MetadataParams.MetadataSetData setData = new MetadataParams.MetadataSetData(message, timestamp.toString(16));
        ECKeyPair derivedECKeyPair = ECKeyPair.create(privateKey);
        // this pubkey is not being padded in backend as well on web, so do not pad here.
        String derivedPubKeyString = derivedECKeyPair.getPublicKey().toString(16);
        String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2);
        String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);

        // Needs to check if this is necessary or not
        /*if (!options.isLegacyNonce()) {
            derivedPubKeyX = Utils.stripPaddingLeft(derivedPubKeyX, '0');
            derivedPubKeyY = Utils.stripPaddingLeft(derivedPubKeyY, '0');
        }*/
        Gson gson = new Gson();
        String setDataString = gson.toJson(setData);
        byte[] hashedData = Hash.sha3(setDataString.getBytes(StandardCharsets.UTF_8));
        ECDSASignature signature = derivedECKeyPair.sign(hashedData);
        String sig = Utils.padLeft(signature.r.toString(16), '0', 64) + Utils.padLeft(signature.s.toString(16), '0', 64) + Utils.padLeft("", '0', 2);
        byte[] sigBytes = AES256CBC.toByteArray(new BigInteger(sig, 16));
        String finalSig = new String(Base64.encodeBytesToBytes(sigBytes), StandardCharsets.UTF_8);
        return new MetadataParams(derivedPubKeyX, derivedPubKeyY, setData, finalSig, KeyType.secp256k1);
    }
}
