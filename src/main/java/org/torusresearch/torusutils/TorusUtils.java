package org.torusresearch.torusutils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.torusresearch.fetchnodedetails.types.TorusNetwork;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.CommitmentRequestParams;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.KeyAssignResult;
import org.torusresearch.torusutils.apis.KeyAssignment;
import org.torusresearch.torusutils.apis.NodeSignature;
import org.torusresearch.torusutils.apis.PubKey;
import org.torusresearch.torusutils.apis.ShareMetadata;
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
import org.torusresearch.torusutils.types.GetOrSetNonceError;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.ImportedShare;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.MetadataParams;
import org.torusresearch.torusutils.types.MetadataPubKey;
import org.torusresearch.torusutils.types.MetadataResponse;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.PrivateKeyWithNonceResult;
import org.torusresearch.torusutils.types.RetrieveSharesResponse;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.SessionToken;
import org.torusresearch.torusutils.types.TorusCtorOptions;
import org.torusresearch.torusutils.types.TorusException;
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
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

import io.reactivex.annotations.Nullable;
import okhttp3.internal.http2.Header;

public class TorusUtils {

    public final TorusCtorOptions options;

    private final BigInteger secp256k1N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    {
        setupBouncyCastle();
    }

    public TorusUtils(TorusCtorOptions options) {
        this.options = options;
    }

    public static void setAPIKey(String apiKey) {
        APIUtils.setApiKey(apiKey);
    }

    public static boolean isGetOrSetNonceError(Exception err) {
        return err instanceof GetOrSetNonceError;
    }

    public static List<String> LEGACY_NETWORKS_ROUTE_MAP = Arrays.asList(TorusNetwork.AQUA.toString(), TorusNetwork.CELESTE.toString(),
            TorusNetwork.CYAN.toString(), TorusNetwork.TESTNET.toString(), TorusNetwork.MAINNET.toString());

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

    public CompletableFuture<RetrieveSharesResponse> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams,
                                                                    String idToken, HashMap<String, Object> extraParams,
                                                                    @Nullable ImportedShare[] importedShares) {
        try {
            APIUtils.get(this.options.getAllowHost(), new Header[]{new Header("Origin", this.options.getOrigin()), new Header("verifier", verifier), new Header("verifier_id", verifierParams.get("verifier_id").toString()), new Header("network", this.options.getNetwork()),
                    new Header("network", this.options.getClientId())}, true).get();
            List<CompletableFuture<String>> promiseArr = new ArrayList<>();
            List<SessionToken> sessionTokenData = new ArrayList<>();
            List<BigInteger> nodeIndexes = new ArrayList<>();
            // generate temporary private and public key that is used to secure receive shares
            ECKeyPair tmpKey = Keys.createEcKeyPair();
            String pubKey = Utils.padLeft(tmpKey.getPublicKey().toString(16), '0', 128);
            String pubKeyX = pubKey.substring(0, pubKey.length() / 2);
            String pubKeyY = pubKey.substring(pubKey.length() / 2);
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
                    if (result != null && !result.equals("")) {
                        completedRequests.add(result);
                    }
                }
                CompletableFuture<List<String>> completableFuture = new CompletableFuture<>();
                if (completedRequests.size() >= k + t) {
                    completableFuture.complete(completedRequests);
                } else {
                    completableFuture.completeExceptionally(new PredicateFailedException("insufficient responses for commitments"));
                }
                return completableFuture;
            }).getCompletableFuture().thenComposeAsync(responses -> {
                try {
                    List<CompletableFuture<String>> promiseArrRequests = new ArrayList<>();
                    List<String> nodeSigs = new ArrayList<>();
                    for (String respons : responses) {
                        if (respons != null && !respons.equals("")) {
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
                        verifierParams.putAll(extraParams);
                    }
                    for (int i = 0; i < endpoints.length; i++) {
                        String req;
                        List<HashMap<String, Object>> shareRequestItems = new ArrayList<>();
                        if (finalIsImportShareReq) {
                            verifierParams.put("pub_key_x", importedShares[i].getPub_key_x());
                            verifierParams.put("pub_key_y", importedShares[i].getPub_key_y());
                            verifierParams.put("encrypted_share", importedShares[i].getEncrypted_share());
                            verifierParams.put("encrypted_share_metadata", importedShares[i].getEncrypted_share());
                            verifierParams.put("node_index", importedShares[i].getNode_index());
                            verifierParams.put("key_type", importedShares[i].getKey_type());
                            verifierParams.put("nonce_data", importedShares[i].getNonce_data());
                            verifierParams.put("nonce_signature", importedShares[i].getNonce_signature());
                            shareRequestItems.add(verifierParams);
                            req = APIUtils.generateJsonRPCObject("ImportShare", new ShareRequestParams(shareRequestItems));
                        } else {
                            shareRequestItems.add(verifierParams);
                            req = APIUtils.generateJsonRPCObject(Utils.getJsonRPCObjectMethodName(this.options.getNetwork()), new ShareRequestParams(shareRequestItems));
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
                            for (String x : completedResponses) {
                                KeyAssignResult keyAssignResult = gson.fromJson(x, KeyAssignResult.class);
                                if (keyAssignResult == null || keyAssignResult.getKeys() == null || keyAssignResult.getKeys().length == 0) {
                                    return null;
                                }
                                KeyAssignment keyAssignResultFirstKey = keyAssignResult.getKeys()[0];
                                completedResponsesPubKeys.add(Utils.convertToJsonObject(keyAssignResultFirstKey.getPublicKey(this.options.getNetwork())));
                                thresholdNonceData = keyAssignResult.getKeys()[0].getNonceData();
                            }
                            String thresholdPublicKeyString = Utils.thresholdSame(completedResponsesPubKeys, k);
                            PubKey thresholdPubKey = null;

                            if (thresholdPublicKeyString == null) {
                                throw new RuntimeException("Invalid result from nodes, threshold number of public key results are not matching");
                            }

                            // If both thresholdNonceData and extended_verifier_id are not available,
                            // then we need to throw an error; otherwise, the address would be incorrect.
                            if (thresholdNonceData == null && verifierParams.get("extended_verifier_id") == null &&
                                    !LEGACY_NETWORKS_ROUTE_MAP.contains(this.options.getNetwork())) {
                                throw new RuntimeException(String.format(
                                        "Invalid metadata result from nodes, nonce metadata is empty for verifier: %s and verifierId: %s",
                                        verifier, verifierParams.get("verifier_id"))
                                );
                            }

                            if (thresholdPublicKeyString != null && !thresholdPublicKeyString.equals("")) {
                                thresholdPubKey = gson.fromJson(thresholdPublicKeyString, PubKey.class);
                            }
                            if (completedResponses.size() >= k && thresholdPubKey != null && (thresholdNonceData != null ||
                                    LEGACY_NETWORKS_ROUTE_MAP.contains(this.options.getNetwork()))) {
                                List<DecryptedShare> decryptedShares = new ArrayList<>();
                                List<CompletableFuture<byte[]>> sharePromises = new ArrayList<>();
                                List<CompletableFuture<byte[]>> sessionTokenSigPromises = new ArrayList<>();
                                List<CompletableFuture<byte[]>> sessionTokenPromises = new ArrayList<>();

                                for (int i = 0; i < shareResponses.length; i++) {
                                    if (shareResponses[i] != null && !shareResponses[i].equals("")) {
                                        try {
                                            JsonRPCResponse currentJsonRPCResponse = gson.fromJson(shareResponses[i], JsonRPCResponse.class);
                                            if (currentJsonRPCResponse != null && currentJsonRPCResponse.getResult() != null && !currentJsonRPCResponse.getResult().equals("")) {
                                                KeyAssignResult currentShareResponse = gson.fromJson(Utils.convertToJsonObject(currentJsonRPCResponse.getResult()), KeyAssignResult.class);

                                                if (currentShareResponse.getSessionTokenSigs() != null && currentShareResponse.getSessionTokenSigs().length > 0) {
                                                    // Decrypt sessionSig if enc metadata is sent
                                                    ShareMetadata[] sessionTokenSigMetaData = currentShareResponse.getSessionTokenSigMetadata();
                                                    if (sessionTokenSigMetaData != null && sessionTokenSigMetaData[0] != null && sessionTokenSigMetaData[0].getEphemPublicKey() != null) {
                                                        try {
                                                            AES256CBC aes256cbc = new AES256CBC(tmpKey.getPrivateKey().toString(16), sessionTokenSigMetaData[0].getEphemPublicKey(),
                                                                    sessionTokenSigMetaData[0].getIv());
                                                            byte[] encryptedShareBytes = AES256CBC.toByteArray(new BigInteger(currentShareResponse.getSessionTokenSigs()[0], 16));
                                                            sessionTokenSigPromises.add(CompletableFuture.completedFuture(aes256cbc.decrypt(Base64.encodeBytes(encryptedShareBytes))));
                                                        } catch (Exception ex) {
                                                            System.out.println("session sig decryption" + ex);
                                                            return null;
                                                        }
                                                    } else {
                                                        sessionTokenSigPromises.add(CompletableFuture.completedFuture(currentShareResponse.getSessionTokenSigs()[0].getBytes(StandardCharsets.UTF_8)));
                                                    }
                                                } else {
                                                    sessionTokenSigPromises.add(CompletableFuture.completedFuture(null));
                                                }

                                                if (currentShareResponse.getSessionTokenSigs() != null && currentShareResponse.getSessionTokenSigs().length > 0) {
                                                    // Decrypt sessionToken if enc metadata is sent
                                                    ShareMetadata[] sessionTokenMetaData = currentShareResponse.getSessionTokenMetadata();
                                                    if (sessionTokenMetaData != null && sessionTokenMetaData[0] != null &&
                                                            currentShareResponse.getSessionTokenMetadata()[0].getEphemPublicKey() != null) {
                                                        try {
                                                            AES256CBC aes256cbc = new AES256CBC(tmpKey.getPrivateKey().toString(16), sessionTokenMetaData[0].getEphemPublicKey(),
                                                                    sessionTokenMetaData[0].getIv());
                                                            byte[] encryptedShareBytes = AES256CBC.toByteArray(new BigInteger(currentShareResponse.getSessionTokens()[0], 16));
                                                            sessionTokenPromises.add(CompletableFuture.completedFuture(aes256cbc.decrypt(Base64.encodeBytes(encryptedShareBytes))));
                                                        } catch (Exception ex) {
                                                            System.out.println("session token decryption" + ex);
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
                                                        nodeIndexes.add(BigInteger.valueOf(firstKey.getNodeIndex()));
                                                    }
                                                    if (firstKey.getMetadata(this.options.getNetwork()) != null) {
                                                        try {
                                                            AES256CBC aes256cbc = new AES256CBC(tmpKey.getPrivateKey().toString(16), firstKey.getMetadata(this.options.getNetwork()).getEphemPublicKey(), firstKey.getMetadata(this.options.getNetwork()).getIv());
                                                            // Implementation specific oddity - hex string actually gets passed as a base64 string
                                                            String hexUTF8AsBase64 = firstKey.getShare(this.options.getNetwork());
                                                            String hexUTF8 = new String(Base64.decode(hexUTF8AsBase64), StandardCharsets.UTF_8);
                                                            byte[] encryptedShareBytes = AES256CBC.toByteArray(new BigInteger(hexUTF8, 16));
                                                            BigInteger share = new BigInteger(1, aes256cbc.decrypt(Base64.encodeBytes(encryptedShareBytes)));
                                                            decryptedShares.add(new DecryptedShare(indexes[i], share));
                                                        } catch (Exception e) {
                                                            e.printStackTrace();
                                                        }
                                                    } else {
                                                        nodeIndexes.add(null);
                                                        sharePromises.add(null);
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

                                                for (int index = 0; index < sessionTokensResolved.size(); index++) {
                                                    if (sessionSigsResolved == null || sessionSigsResolved.get(index) == null) {
                                                        sessionTokenData.add(null);
                                                    } else {
                                                        sessionTokenData.add(new SessionToken(java.util.Base64.getEncoder().encodeToString(sessionSigsResolved.get(index).get()),
                                                                Utils.bytesToHex(sessionSigsResolved.get(index).get()),
                                                                currentShareResponse.getNodePubx(),
                                                                currentShareResponse.getNodePuby()));
                                                    }
                                                }
                                            }
                                        } catch (JsonSyntaxException e) {
                                            continue;
                                        }
                                    }
                                }
                                if (predicateResolved.get()) return null;
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
                                    response.complete(new PrivateKeyWithNonceResult(privateKey, thresholdNonceData));
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
                CompletableFuture<RetrieveSharesResponse> cf = new CompletableFuture<>();
                if (privateKey == null) {
                    cf.completeExceptionally(new TorusException("could not get private key"));
                    return cf;
                }
                try {
                    ECKeyPair oAuthKey = ECKeyPair.create(privateKey);
                    String oAuthPubKey = Utils.padLeft(oAuthKey.getPublicKey().toString(16), '0', 128);
                    String oAuthPubkeyX = oAuthPubKey.substring(0, oAuthPubKey.length() / 2);
                    String oAuthPubkeyY = oAuthPubKey.substring(oAuthPubKey.length() / 2);
                    BigInteger metadataNonce;
                    if (this.options.isEnableOneKey()) {
                        thresholdNonceData = this.getNonce(privateKey).get();
                        metadataNonce = new BigInteger(Utils.isEmpty(thresholdNonceData.getNonce()) ? "0" : thresholdNonceData.getNonce(), 16);
                    } else {
                        metadataNonce = this.getMetadata(new MetadataPubKey(oAuthPubkeyX, oAuthPubkeyY)).get();
                    }
                    privateKey = privateKey.add(metadataNonce).mod(secp256k1N);
                    String oAuthKeyAddress = this.generateAddressFromPrivKey(privateKey.toString(16));
                    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                    ECPoint finalPubKey = null;
                    BigInteger nonce;
                    TypeOfUser typeOfUser = TypeOfUser.v1;
                    if (verifierParams.get("extended_verifier_id") != null) {
                        typeOfUser = TypeOfUser.v2;
                        // for tss key no need to add pub nonce
                        finalPubKey = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                    } else if (LEGACY_NETWORKS_ROUTE_MAP.contains(this.options.getNetwork())) {
                        if (this.options.isEnableOneKey()) {
                            GetOrSetNonceResult nonceResult = this.getNonce(privateKey).get();
                            nonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                            typeOfUser = nonceResult.getTypeOfUser();
                            metadataNonce = new BigInteger(Utils.isEmpty(thresholdNonceData.getNonce()) ? "0" : thresholdNonceData.getNonce(), 16);
                            if (typeOfUser.equals("v2")) {
                                ECPoint oneKeyMetadataPoint = curve.getCurve().createPoint(new BigInteger(nonceResult.getPubNonce().getX(), 16), new BigInteger(nonceResult.getPubNonce().getY(), 16));
                                finalPubKey = finalPubKey.add(oneKeyMetadataPoint).normalize();
                            }
                        } else {
                            typeOfUser = TypeOfUser.v1;
                            metadataNonce = this.getMetadata(new MetadataPubKey(oAuthPubkeyX, oAuthPubkeyY)).get();
                        }
                    } else {
                        typeOfUser = TypeOfUser.v2;
                        ECPoint publicKey = curve.getCurve().createPoint(new BigInteger(oAuthPubkeyX, 16), new BigInteger(oAuthPubkeyY, 16));
                        if (thresholdNonceData != null) {
                            ECPoint noncePublicKey = curve.getCurve().createPoint(new BigInteger(thresholdNonceData.getPubNonce().getX(), 16), new BigInteger(thresholdNonceData.getPubNonce().getY(), 16));
                            finalPubKey = publicKey.add(noncePublicKey);
                        }
                        BigInteger privateKeyWithNonce = privateKey.add(metadataNonce).mod(curve.getN());
                        if (finalPubKey == null) {
                            finalPubKey = finalPubKey.multiply(privateKeyWithNonce).normalize();
                        }
                    }

                    Boolean isUpgraded = false;
                    if (typeOfUser.equals(TypeOfUser.v1)) {
                        isUpgraded = null;
                    } else if (typeOfUser.equals(TypeOfUser.v2)) {
                        isUpgraded = metadataNonce.equals(BigInteger.ZERO);
                    }

                    return CompletableFuture.completedFuture(new RetrieveSharesResponse(new FinalKeyData(oAuthKeyAddress,
                            finalPubKey != null ? finalPubKey.getXCoord().toString() : null,
                            finalPubKey != null ? finalPubKey.getYCoord().toString() : null,
                            privateKey.toString(16)),
                            new OAuthKeyData(oAuthKeyAddress, oAuthPubkeyX, oAuthPubkeyY, Utils.padLeft(oAuthPubKey, '0', 64)),
                            new SessionData(sessionTokenData, pubKey),
                            new Metadata(metadataNonce, typeOfUser, isUpgraded),
                            new NodesData(nodeIndexes)
                    ));

                } catch (Exception ex) {
                    CompletableFuture<RetrieveSharesResponse> cfRes = new CompletableFuture<>();
                    cfRes.completeExceptionally(new TorusException("Torus Internal Error", ex));
                    return cfRes;
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            CompletableFuture<RetrieveSharesResponse> cfRes = new CompletableFuture<>();
            cfRes.completeExceptionally(new TorusException("Torus Internal Error", e));
            return cfRes;
        }
    }

    public CompletableFuture<RetrieveSharesResponse> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams, String idToken, @Nullable ImportedShare[] importedShares) {
        return this.retrieveShares(endpoints, indexes, verifier, verifierParams, idToken, null, importedShares);
    }

    public CompletableFuture<RetrieveSharesResponse> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams, String idToken) {
        return this.retrieveShares(endpoints, indexes, verifier, verifierParams, idToken, null, new ImportedShare[]{});
    }

    public CompletableFuture<BigInteger> getMetadata(MetadataPubKey data) {
        try {
            Gson gson = new Gson();
            String metadata = gson.toJson(data, MetadataPubKey.class);
            String metadataApiResponse = APIUtils.post(this.options.getMetadataHost() + "/get", metadata, true).get();
            MetadataResponse response = gson.fromJson(metadataApiResponse, MetadataResponse.class);
            BigInteger finalResponse = new BigInteger(Utils.isEmpty(response.getMessage()) ? "0" : response.getMessage(), 16);
            return CompletableFuture.supplyAsync(() -> finalResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return CompletableFuture.supplyAsync(() -> new BigInteger("0"));
        }
    }

    public MetadataParams generateMetadataParams(String message, BigInteger privateKey) {
        long timeMillis = System.currentTimeMillis() / 1000L;
        BigInteger timestamp = this.options.getServerTimeOffset().add(new BigInteger(String.valueOf(timeMillis)));
        MetadataParams.MetadataSetData setData = new MetadataParams.MetadataSetData(message, timestamp.toString(16));
        ECKeyPair derivedECKeyPair = ECKeyPair.create(privateKey);
        String derivedPubKeyString = Utils.padLeft(derivedECKeyPair.getPublicKey().toString(16), '0', 128);
        String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2);
        String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);
        if (!options.isLegacyNonce()) {
            derivedPubKeyX = Utils.stripPaddingLeft(derivedPubKeyX, '0');
            derivedPubKeyY = Utils.stripPaddingLeft(derivedPubKeyY, '0');
        }
        Gson gson = new Gson();
        String setDataString = gson.toJson(setData);
        byte[] hashedData = Hash.sha3(setDataString.getBytes(StandardCharsets.UTF_8));
        ECDSASignature signature = derivedECKeyPair.sign(hashedData);
        String sig = Utils.padLeft(signature.r.toString(16), '0', 64) + Utils.padLeft(signature.s.toString(16), '0', 64) + Utils.padLeft("", '0', 2);
        byte[] sigBytes = AES256CBC.toByteArray(new BigInteger(sig, 16));
        String finalSig = new String(Base64.encodeBytesToBytes(sigBytes), StandardCharsets.UTF_8);
        return new MetadataParams(derivedPubKeyX, derivedPubKeyY, setData, finalSig);
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

    CompletableFuture<TorusPublicKey> _getLegacyPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs, boolean isExtended) {
        AtomicBoolean isNewKey = new AtomicBoolean(false);
        Gson gson = new Gson();
        return Utils.keyLookup(endpoints, verifierArgs.getVerifier(), verifierArgs.getVerifierId()).thenComposeAsync(keyLookupResult -> {
            if (keyLookupResult.getErrResult() != null && keyLookupResult.getErrResult().contains("Verifier not supported")) {
                CompletableFuture<VerifierLookupItem> lookupCf = new CompletableFuture<>();
                lookupCf.completeExceptionally(new Exception("Verifier not supported. Check if you: \\n\n" + "      1. Are on the right network (Torus testnet/mainnet) \\n\n" + "      2. Have setup a verifier on dashboard.web3auth.io?"));
                return lookupCf;
            } else if (keyLookupResult.getErrResult() != null && keyLookupResult.getErrResult().contains("Verifier + VerifierID has not yet been assigned")) {
                return Utils.keyAssign(endpoints, torusNodePubs, null, null, verifierArgs.getVerifier(), verifierArgs.getVerifierId(), this.options.getSignerHost(), this.options.getNetwork()).thenComposeAsync(k -> Utils.waitKeyLookup(endpoints, verifierArgs.getVerifier(), verifierArgs.getVerifierId(), 1000)).thenComposeAsync(res -> {
                    CompletableFuture<VerifierLookupItem> lookupCf = new CompletableFuture<>();
                    try {
                        if (res == null || res.getKeyResult() == null) {
                            lookupCf.completeExceptionally(new Exception("could not get lookup, no results"));
                            return lookupCf;
                        }
                        VerifierLookupRequestResult verifierLookupRequestResult = gson.fromJson(res.getKeyResult(), VerifierLookupRequestResult.class);
                        if (verifierLookupRequestResult == null || verifierLookupRequestResult.getKeys() == null || verifierLookupRequestResult.getKeys().length == 0) {
                            lookupCf.completeExceptionally(new Exception("could not get lookup, no keys" + res.getKeyResult() + res.getErrResult()));
                            return lookupCf;
                        }
                        VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                        lookupCf.complete(verifierLookupItem);
                        isNewKey.set(true);
                    } catch (Exception ex) {
                        lookupCf.completeExceptionally(ex);
                    }
                    return lookupCf;
                });
            }
            CompletableFuture<VerifierLookupItem> lookupCf = new CompletableFuture<>();
            try {
                if (keyLookupResult.getKeyResult() != null) {
                    VerifierLookupRequestResult verifierLookupRequestResult = gson.fromJson(keyLookupResult.getKeyResult(), VerifierLookupRequestResult.class);
                    if (verifierLookupRequestResult == null || verifierLookupRequestResult.getKeys() == null || verifierLookupRequestResult.getKeys().length == 0) {
                        lookupCf.completeExceptionally(new Exception("could not get lookup, no keys" + keyLookupResult.getKeyResult() + keyLookupResult.getErrResult()));
                        return lookupCf;
                    }
                    VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                    lookupCf.complete(verifierLookupItem);
                    return lookupCf;
                }
                lookupCf.completeExceptionally(new Exception("could not get lookup, no valid key result or error result"));
            } catch (Exception ex) {
                lookupCf.completeExceptionally(ex);
            }
            return lookupCf;
        }).thenComposeAsync(verifierLookupItem -> {
            CompletableFuture<TorusPublicKey> keyCf = new CompletableFuture<>();
            try {
                GetOrSetNonceResult nonceResult = null;
                BigInteger nonce;
                ECPoint modifiedPubKey;
                TypeOfUser typeOfUser;
                GetOrSetNonceResult.PubNonce pubNonce = null;
                ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                if (this.options.isEnableOneKey()) {
                    try {
                        nonceResult = this.getOrSetNonce(verifierLookupItem.getPub_key_X(), verifierLookupItem.getPub_key_Y(), !isNewKey.get()).get();
                        nonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                        typeOfUser = nonceResult.getTypeOfUser();
                    } catch (Exception e) {
                        // Sometimes we take special action if `get or set nonce` api is not available
                        keyCf.completeExceptionally(new GetOrSetNonceError(e));
                        return keyCf;
                    }

                    modifiedPubKey = curve.getCurve().createPoint(new BigInteger(verifierLookupItem.getPub_key_X(), 16), new BigInteger(verifierLookupItem.getPub_key_Y(), 16));
                    if (nonceResult.getTypeOfUser() == TypeOfUser.v1) {
                        modifiedPubKey = modifiedPubKey.add(curve.getG().multiply(nonce)).normalize();
                    } else if (nonceResult.getTypeOfUser() == TypeOfUser.v2) {
                        if (!nonceResult.isUpgraded()) {
                            assert nonceResult.getPubNonce() != null;
                            ECPoint oneKeyMetadataPoint = curve.getCurve().createPoint(new BigInteger(nonceResult.getPubNonce().getX(), 16), new BigInteger(nonceResult.getPubNonce().getY(), 16));
                            modifiedPubKey = modifiedPubKey.add(oneKeyMetadataPoint).normalize();
                            pubNonce = nonceResult.getPubNonce();
                        }
                    } else {
                        keyCf.completeExceptionally(new Exception("getOrSetNonce should always return typeOfUser."));
                        return keyCf;
                    }
                } else {
                    typeOfUser = TypeOfUser.v1;
                    nonce = this.getMetadata(new MetadataPubKey(verifierLookupItem.getPub_key_X(), verifierLookupItem.getPub_key_Y())).get();
                    modifiedPubKey = curve.getCurve().createPoint(new BigInteger(verifierLookupItem.getPub_key_X(), 16), new BigInteger(verifierLookupItem.getPub_key_Y(), 16));
                    modifiedPubKey = modifiedPubKey.add(curve.getG().multiply(nonce)).normalize();
                }
                String finalPubKey = Utils.padLeft(modifiedPubKey.getAffineXCoord().toString(), '0', 64) + Utils.padLeft(modifiedPubKey.getAffineYCoord().toString(), '0', 64);
                String address = Keys.toChecksumAddress(Hash.sha3(finalPubKey).substring(64 - 38));
                if (!isExtended) {
                    keyCf.complete(new TorusPublicKey(address));
                } else {
                    TorusPublicKey key = new TorusPublicKey(finalPubKey.substring(0, finalPubKey.length() / 2), finalPubKey.substring(finalPubKey.length() / 2), address);
                    key.setTypeOfUser(typeOfUser);
                    key.setMetadataNonce(nonce);
                    key.setPubNonce(pubNonce);
                    key.setUpgraded(nonceResult != null && nonceResult.isUpgraded());
                    keyCf.complete(key);
                }
                return keyCf;
            } catch (Exception ex) {
                keyCf.completeExceptionally(ex);
                return keyCf;
            }
        });
    }

    public CompletableFuture<TorusPublicKey> _getPublicAddress(String[] endpoints, VerifierArgs verifierArgs, boolean isExtended) {
        System.out.println("> torusUtils.java/getPublicAddress " + endpoints + " " + verifierArgs + " " + isExtended);
        AtomicBoolean isNewKey = new AtomicBoolean(false);
        Gson gson = new Gson();
        return Utils.getPubKeyOrKeyAssign(endpoints, this.options.getNetwork(), verifierArgs.getVerifier(), verifierArgs.getVerifierId(), verifierArgs.getExtendedVerifierId())
                .thenApply(keyAssignResult -> {
                    String errorResult = keyAssignResult.getErrResult();
                    String keyResult = keyAssignResult.getKeyResult();
                    List<Integer> nodeIndexes = keyAssignResult.getNodeIndexes();
                    GetOrSetNonceResult nonceResult = keyAssignResult.getNonceResult();

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
                            !LEGACY_NETWORKS_ROUTE_MAP.contains(this.options.getNetwork())) {
                        try {
                            throw new GetOrSetNonceError(new Exception("metadata nonce is missing in share response"));
                        } catch (GetOrSetNonceError e) {
                            e.printStackTrace();
                        }
                    }

                    VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                    isNewKey.set(true);
                    String X = verifierLookupItem.getPub_key_X();
                    String Y = verifierLookupRequestResult.getKeys()[0].getPub_key_Y();
                    ECPoint modifiedPubKey;
                    TypeOfUser typeOfUser = null;
                    GetOrSetNonceResult.PubNonce pubNonce = null;
                    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                    BigInteger nonce = new BigInteger(nonceResult != null ? nonceResult.getNonce() : "0", 16);
                    CompletableFuture<TorusPublicKey> keyCf = new CompletableFuture<>();

                    if (verifierArgs.getExtendedVerifierId() != null) {
                        modifiedPubKey = Utils.getPublicKeyFromHex(X, Y);
                    } else if (LEGACY_NETWORKS_ROUTE_MAP.contains(this.options.getNetwork())) {
                        if (this.options.isEnableOneKey()) {
                            try {
                                nonceResult = this.getOrSetNonce(verifierLookupItem.getPub_key_X(), verifierLookupItem.getPub_key_Y(), !isNewKey.get()).get();
                                nonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                                typeOfUser = nonceResult.getTypeOfUser();
                            } catch (Exception e) {
                                // Sometimes we take special action if `get or set nonce` api is not available
                                try {
                                    throw new GetOrSetNonceError(e);
                                } catch (GetOrSetNonceError ex) {
                                    ex.printStackTrace();
                                }
                            }

                            modifiedPubKey = curve.getCurve().createPoint(new BigInteger(verifierLookupItem.getPub_key_X(), 16), new BigInteger(verifierLookupItem.getPub_key_Y(), 16));
                            if (nonceResult.getTypeOfUser() == TypeOfUser.v1) {
                                modifiedPubKey = modifiedPubKey.add(curve.getG().multiply(nonce)).normalize();
                            } else if (nonceResult.getTypeOfUser() == TypeOfUser.v2) {
                                if (!nonceResult.isUpgraded()) {
                                    assert nonceResult.getPubNonce() != null;
                                    ECPoint oneKeyMetadataPoint = curve.getCurve().createPoint(new BigInteger(nonceResult.getPubNonce().getX(), 16), new BigInteger(nonceResult.getPubNonce().getY(), 16));
                                    modifiedPubKey = modifiedPubKey.add(oneKeyMetadataPoint).normalize();
                                    pubNonce = nonceResult.getPubNonce();
                                }
                            } else {
                                throw new RuntimeException("getOrSetNonce should always return typeOfUser.");
                            }
                        } else {
                            typeOfUser = TypeOfUser.v1;
                            try {
                                nonce = this.getMetadata(new MetadataPubKey(verifierLookupItem.getPub_key_X(), verifierLookupItem.getPub_key_Y())).get();
                            } catch (Exception ex) {
                                throw new RuntimeException("getMetadata API error.");
                            }
                            modifiedPubKey = curve.getCurve().createPoint(new BigInteger(verifierLookupItem.getPub_key_X(), 16), new BigInteger(verifierLookupItem.getPub_key_Y(), 16));
                            modifiedPubKey = modifiedPubKey.add(curve.getG().multiply(nonce)).normalize();
                        }
                    } else {
                        ECPoint pubKey = Utils.getPublicKeyFromHex(X, Y);
                        ECPoint noncePubKey = Utils.getPublicKeyFromHex(nonceResult.getPubNonce().getX(), nonceResult.getPubNonce().getY());
                        modifiedPubKey = pubKey.add(noncePubKey);
                        pubNonce = nonceResult.getPubNonce();
                    }

                    X = modifiedPubKey.normalize().getAffineXCoord().toBigInteger().toString(16);
                    Y = modifiedPubKey.normalize().getAffineYCoord().toBigInteger().toString(16);

                    String address = generateAddressFromPubKey(modifiedPubKey.normalize().getAffineXCoord().toBigInteger(), modifiedPubKey.normalize().getAffineYCoord().toBigInteger());
                    System.out.println("> torusUtils.java/getPublicAddress " + X + " " + Y + " " + address + " " + nonce.toString(16) + " " + pubNonce);

                    if (!isExtended) {
                        return new TorusPublicKey(address);
                    } else {
                        return new TorusPublicKey(address, X, Y, nonce, pubNonce, nonceResult != null && nonceResult.isUpgraded(),
                                nodeIndexes, typeOfUser);
                    }
                });
    }


    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, VerifierArgs verifierArgs, boolean isExtended) {
        return _getPublicAddress(endpoints, verifierArgs, isExtended);
    }

    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, VerifierArgs verifierArgs) {
        return _getPublicAddress(endpoints, verifierArgs, false);
    }

    public CompletableFuture<TorusPublicKey> getLegacyPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs, boolean isExtended) {
        return _getLegacyPublicAddress(endpoints, torusNodePubs, verifierArgs, isExtended);
    }

    public CompletableFuture<TorusPublicKey> getLegacyPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs) {
        return _getLegacyPublicAddress(endpoints, torusNodePubs, verifierArgs, false);
    }

    private CompletableFuture<GetOrSetNonceResult> _getOrSetNonce(MetadataParams data) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        String finalData = gson.toJson(data);
        CompletableFuture<GetOrSetNonceResult> cf = new CompletableFuture<>();
        APIUtils.post(this.options.getMetadataHost() + "/get_or_set_nonce", finalData, true).whenCompleteAsync((res, ex) -> {
            if (ex != null) {
                cf.completeExceptionally(ex);
                return;
            }
            try {
                GetOrSetNonceResult result = gson.fromJson(res, GetOrSetNonceResult.class);
                cf.complete(result);
            } catch (Exception ex2) {
                cf.completeExceptionally(ex2);
            }
        });
        return cf;
    }

    public CompletableFuture<GetOrSetNonceResult> getOrSetNonce(String X, String Y, boolean getOnly) {
        String msg = getOnly ? "getNonce" : "getOrSetNonce";
        MetadataParams data = new MetadataParams(X, Y, new MetadataParams.MetadataSetData(msg, null), null);
        return this._getOrSetNonce(data);
    }

    public CompletableFuture<GetOrSetNonceResult> getOrSetNonce(BigInteger privKey, boolean getOnly) {
        String msg = getOnly ? "getNonce" : "getOrSetNonce";
        MetadataParams data = this.generateMetadataParams(msg, privKey);
        return this._getOrSetNonce(data);
    }

    public CompletableFuture<GetOrSetNonceResult> getNonce(String X, String Y) {
        return this.getOrSetNonce(X, Y, true);
    }

    public CompletableFuture<GetOrSetNonceResult> getNonce(BigInteger privKey) {
        return this.getOrSetNonce(privKey, true);
    }

    public CompletableFuture<TorusPublicKey> getUserTypeAndAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs) {
        return this.getUserTypeAndAddress(endpoints, torusNodePubs, verifierArgs, false);
    }

    public CompletableFuture<TorusPublicKey> getUserTypeAndAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs, boolean doesKeyAssign) {
        AtomicBoolean isNewKey = new AtomicBoolean(false);
        Gson gson = new Gson();
        return Utils.keyLookup(endpoints, verifierArgs.getVerifier(), verifierArgs.getVerifierId()).thenComposeAsync(keyLookupResult -> {
            if (keyLookupResult.getErrResult() != null && keyLookupResult.getErrResult().contains("Verifier not supported")) {
                CompletableFuture<VerifierLookupItem> lookupCf = new CompletableFuture<>();
                lookupCf.completeExceptionally(new Exception("Verifier not supported. Check if you: \\n\n" + "      1. Are on the right network (Torus testnet/mainnet) \\n\n" + "      2. Have setup a verifier on dashboard.web3auth.io?"));
                return lookupCf;
            } else if (keyLookupResult.getErrResult() != null && keyLookupResult.getErrResult().contains("Verifier + VerifierID has not yet been assigned")) {
                if (!doesKeyAssign) {
                    CompletableFuture<VerifierLookupItem> lookupCf = new CompletableFuture<>();
                    lookupCf.completeExceptionally(new Exception("Verifier + VerifierID has not yet been assigned"));
                    return lookupCf;
                }
                return Utils.keyAssign(endpoints, torusNodePubs, null, null, verifierArgs.getVerifier(), verifierArgs.getVerifierId(), this.options.getSignerHost(), this.options.getNetwork()).thenComposeAsync(k -> Utils.waitKeyLookup(endpoints, verifierArgs.getVerifier(), verifierArgs.getVerifierId(), 1000)).thenComposeAsync(res -> {
                    CompletableFuture<VerifierLookupItem> lookupCf = new CompletableFuture<>();
                    try {
                        if (res == null || res.getKeyResult() == null) {
                            lookupCf.completeExceptionally(new Exception("could not get lookup, no results"));
                            return lookupCf;
                        }
                        VerifierLookupRequestResult verifierLookupRequestResult = gson.fromJson(res.getKeyResult(), VerifierLookupRequestResult.class);
                        if (verifierLookupRequestResult == null || verifierLookupRequestResult.getKeys() == null || verifierLookupRequestResult.getKeys().length == 0) {
                            lookupCf.completeExceptionally(new Exception("could not get lookup, no keys" + res.getKeyResult() + res.getErrResult()));
                            return lookupCf;
                        }
                        VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                        lookupCf.complete(verifierLookupItem);
                        isNewKey.set(true);
                    } catch (Exception ex) {
                        lookupCf.completeExceptionally(ex);
                    }
                    return lookupCf;
                });
            }
            CompletableFuture<VerifierLookupItem> lookupCf = new CompletableFuture<>();
            try {
                if (keyLookupResult.getKeyResult() != null) {
                    VerifierLookupRequestResult verifierLookupRequestResult = gson.fromJson(keyLookupResult.getKeyResult(), VerifierLookupRequestResult.class);
                    if (verifierLookupRequestResult == null || verifierLookupRequestResult.getKeys() == null || verifierLookupRequestResult.getKeys().length == 0) {
                        lookupCf.completeExceptionally(new Exception("could not get lookup, no keys" + keyLookupResult.getKeyResult() + keyLookupResult.getErrResult()));
                        return lookupCf;
                    }
                    VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                    lookupCf.complete(verifierLookupItem);
                    return lookupCf;
                }
                lookupCf.completeExceptionally(new Exception("could not get lookup, no valid key result or error result"));
            } catch (Exception ex) {
                lookupCf.completeExceptionally(ex);
            }
            return lookupCf;
        }).thenComposeAsync(verifierLookupItem -> {
            CompletableFuture<TorusPublicKey> keyCf = new CompletableFuture<>();
            try {
                GetOrSetNonceResult nonceResult;
                BigInteger nonce;
                ECPoint modifiedPubKey;
                TypeOfUser typeOfUser;
                GetOrSetNonceResult.PubNonce pubNonce = null;
                ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");

                try {
                    nonceResult = this.getOrSetNonce(verifierLookupItem.getPub_key_X(), verifierLookupItem.getPub_key_Y(), !isNewKey.get()).get();
                    nonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                    typeOfUser = nonceResult.getTypeOfUser();
                } catch (Exception e) {
                    // Sometimes we take special action if `get or set nonce` api is not available
                    keyCf.completeExceptionally(new GetOrSetNonceError(e));
                    return keyCf;
                }

                modifiedPubKey = curve.getCurve().createPoint(new BigInteger(verifierLookupItem.getPub_key_X(), 16), new BigInteger(verifierLookupItem.getPub_key_Y(), 16));
                if (nonceResult.getTypeOfUser() == TypeOfUser.v1) {
                    modifiedPubKey = modifiedPubKey.add(curve.getG().multiply(nonce)).normalize();
                } else if (nonceResult.getTypeOfUser() == TypeOfUser.v2) {
                    // pubNonce is never deleted, so we can use it to always get the tkey
                    assert nonceResult.getPubNonce() != null;
                    ECPoint oneKeyMetadataPoint = curve.getCurve().createPoint(new BigInteger(nonceResult.getPubNonce().getX(), 16), new BigInteger(nonceResult.getPubNonce().getY(), 16));
                    modifiedPubKey = modifiedPubKey.add(oneKeyMetadataPoint).normalize();
                    pubNonce = nonceResult.getPubNonce();
                } else {
                    keyCf.completeExceptionally(new Exception("getOrSetNonce should always return typeOfUser."));
                    return keyCf;
                }

                String finalPubKey = Utils.padLeft(modifiedPubKey.getAffineXCoord().toString(), '0', 64) + Utils.padLeft(modifiedPubKey.getAffineYCoord().toString(), '0', 64);
                String address = Keys.toChecksumAddress(Hash.sha3(finalPubKey).substring(64 - 38));

                TorusPublicKey key = new TorusPublicKey(finalPubKey.substring(0, finalPubKey.length() / 2), finalPubKey.substring(finalPubKey.length() / 2), address);
                key.setTypeOfUser(typeOfUser);
                key.setMetadataNonce(nonce);
                key.setPubNonce(pubNonce);
                key.setUpgraded(nonceResult.isUpgraded());
                keyCf.complete(key);

                return keyCf;
            } catch (Exception ex) {
                keyCf.completeExceptionally(ex);
                return keyCf;
            }
        });
    }

}
