package org.torusresearch.torusutils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.CommitmentRequestParams;
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
import org.torusresearch.torusutils.types.GetOrSetNonceError;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.ImportedShare;
import org.torusresearch.torusutils.types.MetadataParams;
import org.torusresearch.torusutils.types.MetadataPubKey;
import org.torusresearch.torusutils.types.MetadataResponse;
import org.torusresearch.torusutils.types.RetrieveSharesResponse;
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
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

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

    public CompletableFuture<RetrieveSharesResponse> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams, String idToken, HashMap<String, Object> extraParams, ImportedShare[] importedShares) {
        try {
            APIUtils.get(this.options.getAllowHost(), new Header[]{new Header("Origin", this.options.getOrigin()), new Header("verifier", verifier), new Header("verifier_id", verifierParams.get("verifier_id").toString()), new Header("network", this.options.getNetwork()),
                    new Header("network", this.options.getClientId())}, true).get();
            List<CompletableFuture<String>> promiseArr = new ArrayList<>();
            // generate temporary private and public key that is used to secure receive shares
            ECKeyPair tmpKey = Keys.createEcKeyPair();
            String pubKey = Utils.padLeft(tmpKey.getPublicKey().toString(16), '0', 128);
            String pubKeyX = pubKey.substring(0, pubKey.length() / 2);
            String pubKeyY = pubKey.substring(pubKey.length() / 2);
            String tokenCommitment = org.web3j.crypto.Hash.sha3String(idToken);
            int t = endpoints.length / 4;
            int k = t * 2 + 1;

            boolean isImportShareReq = false;
            if (importedShares.length > 0) {
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
                    List<HashMap<String, Object>> shareRequestItems = new ArrayList<HashMap<String, Object>>() {{
                        add(verifierParams);
                    }};
                    for (String endpoint : endpoints) {
                        String req;
                        if (finalIsImportShareReq) {
                            req = APIUtils.generateJsonRPCObject("ImportShare", new ShareRequestParams(shareRequestItems));
                        } else {
                            req = APIUtils.generateJsonRPCObject("GetShareOrKeyAssign", new ShareRequestParams(shareRequestItems));
                        }
                        promiseArrRequests.add(APIUtils.post(endpoint, req, true));
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
                            for (String x : completedResponses) {
                                KeyAssignResult keyAssignResult = gson.fromJson(x, KeyAssignResult.class);
                                if (keyAssignResult == null || keyAssignResult.getKeys() == null || keyAssignResult.getKeys().length == 0) {
                                    return null;
                                }
                                KeyAssignment keyAssignResultFirstKey = keyAssignResult.getKeys()[0];
                                completedResponsesPubKeys.add(Utils.convertToJsonObject(keyAssignResultFirstKey.getPublicKey()));
                            }
                            String thresholdPublicKeyString = Utils.thresholdSame(completedResponsesPubKeys, k);
                            PubKey thresholdPubKey = null;
                            if (thresholdPublicKeyString != null && !thresholdPublicKeyString.equals("")) {
                                thresholdPubKey = gson.fromJson(thresholdPublicKeyString, PubKey.class);
                            }
                            if (completedResponses.size() >= k && thresholdPubKey != null) {
                                List<DecryptedShare> decryptedShares = new ArrayList<>();
                                for (int i = 0; i < shareResponses.length; i++) {
                                    if (shareResponses[i] != null && !shareResponses[i].equals("")) {
                                        try {
                                            JsonRPCResponse currentJsonRPCResponse = gson.fromJson(shareResponses[i], JsonRPCResponse.class);
                                            if (currentJsonRPCResponse != null && currentJsonRPCResponse.getResult() != null && !currentJsonRPCResponse.getResult().equals("")) {
                                                KeyAssignResult currentShareResponse = gson.fromJson(Utils.convertToJsonObject(currentJsonRPCResponse.getResult()), KeyAssignResult.class);
                                                if (currentShareResponse != null && currentShareResponse.getKeys() != null && currentShareResponse.getKeys().length > 0) {
                                                    KeyAssignment firstKey = currentShareResponse.getKeys()[0];
                                                    if (firstKey.getMetadata() != null) {
                                                        try {
                                                            AES256CBC aes256cbc = new AES256CBC(tmpKey.getPrivateKey().toString(16), firstKey.getMetadata().getEphemPublicKey(), firstKey.getMetadata().getIv());
                                                            // Implementation specific oddity - hex string actually gets passed as a base64 string
                                                            String hexUTF8AsBase64 = firstKey.getShare();
                                                            String hexUTF8 = new String(Base64.decode(hexUTF8AsBase64), StandardCharsets.UTF_8);
                                                            byte[] encryptedShareBytes = AES256CBC.toByteArray(new BigInteger(hexUTF8, 16));
                                                            BigInteger share = new BigInteger(1, aes256cbc.decrypt(Base64.encodeBytes(encryptedShareBytes)));
                                                            decryptedShares.add(new DecryptedShare(indexes[i], share));
                                                        } catch (Exception e) {
                                                            e.printStackTrace();
                                                        }
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
                                CompletableFuture<BigInteger> response = new CompletableFuture<>();
                                if (privateKey == null) {
                                    response.completeExceptionally(new PredicateFailedException("could not derive private key"));
                                } else {
                                    response.complete(privateKey);
                                }
                                return response;
                            } else {
                                CompletableFuture<BigInteger> response = new CompletableFuture<>();
                                response.completeExceptionally(new PredicateFailedException("could not get enough shares"));
                                return response;
                            }
                        } catch (Exception ex) {
                            CompletableFuture<BigInteger> cfRes = new CompletableFuture<>();
                            cfRes.completeExceptionally(new TorusException("Torus Internal Error", ex));
                            return cfRes;
                        }
                    }).getCompletableFuture();
                } catch (Exception ex) {
                    CompletableFuture<BigInteger> cfRes = new CompletableFuture<>();
                    cfRes.completeExceptionally(new TorusException("Torus Internal Error", ex));
                    return cfRes;
                }
            }).thenComposeAsync((privateKey) -> {
                CompletableFuture<RetrieveSharesResponse> cf = new CompletableFuture<>();
                if (privateKey == null) {
                    cf.completeExceptionally(new TorusException("could not get private key"));
                    return cf;
                }
                try {
                    ECKeyPair derivedECKeyPair = ECKeyPair.create(privateKey);
                    String derivedPubKeyString = Utils.padLeft(derivedECKeyPair.getPublicKey().toString(16), '0', 128);
                    String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2);
                    String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);
                    BigInteger metadataNonce;
                    GetOrSetNonceResult nonceResult = null;
                    if (this.options.isEnableOneKey()) {
                        nonceResult = this.getNonce(privateKey).get();
                        metadataNonce = new BigInteger(Utils.isEmpty(nonceResult.getNonce()) ? "0" : nonceResult.getNonce(), 16);
                    } else {
                        metadataNonce = this.getMetadata(new MetadataPubKey(derivedPubKeyX, derivedPubKeyY)).get();
                    }
                    privateKey = privateKey.add(metadataNonce).mod(secp256k1N);
                    String ethAddress = this.generateAddressFromPrivKey(privateKey.toString(16));
                    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                    ECPoint modifiedPubKey;
                    if (verifierParams.get("extended_verifier_id") != null) {
                        // for tss key no need to add pub nonce
                        modifiedPubKey = curve.getCurve().createPoint(new BigInteger(derivedPubKeyX, 16), new BigInteger(derivedPubKeyY, 16));
                    } else {
                        ECPoint publicKey = curve.getCurve().createPoint(new BigInteger(derivedPubKeyX, 16), new BigInteger(derivedPubKeyY, 16));
                        ECPoint noncePublicKey = curve.getCurve().createPoint(new BigInteger(nonceResult.getPubNonce().getX(), 16), new BigInteger(nonceResult.getPubNonce().getY(), 16));
                        modifiedPubKey = publicKey.add(noncePublicKey);
                    }

                    return CompletableFuture.completedFuture(new RetrieveSharesResponse(ethAddress,
                            privateKey,
                            metadataNonce,
                            sessionTokens,
                            modifiedPubKey.getXCoord().toString(),
                            modifiedPubKey.getXCoord().toString(),
                            derivedPubKeyX,
                            derivedPubKeyY,
                            pubKey,
                            nodeIndexes
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

    public CompletableFuture<RetrieveSharesResponse> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier, HashMap<String, Object> verifierParams, String idToken) {
        return this.retrieveShares(endpoints, indexes, verifier, verifierParams, idToken, null, options.getClientId(), new ImportedShare());
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

    CompletableFuture<TorusPublicKey> _getPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs, boolean isExtended) {
        AtomicBoolean isNewKey = new AtomicBoolean(false);
        Gson gson = new Gson();
        return Utils.keyLookup(endpoints, verifierArgs.getVerifier(), verifierArgs.getVerifierId(), verifierArgs.getExtendedVerifierId()).thenComposeAsync(keyLookupResult -> {
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

    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs, boolean isExtended) {
        return _getPublicAddress(endpoints, torusNodePubs, verifierArgs, isExtended);
    }

    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs) {
        return _getPublicAddress(endpoints, torusNodePubs, verifierArgs, false);
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

}
