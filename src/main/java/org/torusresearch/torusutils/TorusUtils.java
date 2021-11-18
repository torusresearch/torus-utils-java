package org.torusresearch.torusutils;

import com.google.gson.Gson;
import java8.util.concurrent.CompletableFuture;
import okhttp3.internal.http2.Header;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.*;
import org.torusresearch.torusutils.helpers.*;
import org.torusresearch.torusutils.types.*;
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

public class TorusUtils {

    private final BigInteger secp256k1N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private final String metadataHost;
    private final String allowHost;
    private final String origin;

    {
        setupBouncyCastle();
    }

    public TorusUtils() {
        this("https://metadata.tor.us", "https://signer.tor.us/api/allow");
    }

    public TorusUtils(String origin) {
        this("https://metadata.tor.us", "https://signer.tor.us/api/allow", origin);
    }

    public TorusUtils(String metadataHost, String allowHost) {
        this(metadataHost, allowHost, "Custom");
    }

    public TorusUtils(String metadataHost, String allowHost, String origin) {
        this.metadataHost = metadataHost;
        this.allowHost = allowHost;
        this.origin = origin;
    }

    public static void setAPIKey(String apiKey) {
        APIUtils.setApiKey(apiKey);
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

    public CompletableFuture<RetrieveSharesResponse> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier,
                                                                    HashMap<String, Object> verifierParams, String idToken, HashMap<String, Object> extraParams) throws TorusException {
        try {
            APIUtils.get(this.allowHost, new Header[]{new Header("Origin", this.origin),
                    new Header("verifier", verifier), new Header("verifier_id", verifierParams.get("verifier_id").toString())}, true).join();
            List<CompletableFuture<String>> promiseArr = new ArrayList<>();
            // generate temporary private and public key that is used to secure receive shares
            ECKeyPair tmpKey = Keys.createEcKeyPair();
            String pubKey = tmpKey.getPublicKey().toString(16);
            String pubKeyX = pubKey.substring(0, pubKey.length() / 2);
            String pubKeyY = pubKey.substring(pubKey.length() / 2);
            String tokenCommitment = org.web3j.crypto.Hash.sha3String(idToken);
            int t = endpoints.length / 4;
            int k = t * 2 + 1;

            // make commitment requests to endpoints
            for (int i = 0; i < endpoints.length; i++) {
                CompletableFuture<String> p = APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("CommitmentRequest",
                        new CommitmentRequestParams("mug00", tokenCommitment.substring(2), pubKeyX, pubKeyY, String.valueOf(System.currentTimeMillis()), verifier)), false);
                promiseArr.add(i, p);
            }
            // send share request once k + t number of commitment requests have completed
            return new Some<>(promiseArr, (resultArr, commitmentsResolved) -> {
                List<String> completedRequests = new ArrayList<>();
                for (String result :
                        resultArr) {
                    if (result != null && !result.equals("")) {
                        completedRequests.add(result);
                    }
                }
                CompletableFuture<List<String>> completableFuture = new CompletableFuture<>();
                if (completedRequests.size() >= k + t) {
                    completableFuture.complete(completedRequests);
                    return completableFuture;
                } else {
                    throw new PredicateFailedException("insufficient responses for commitments");
                }
            })
                    .getCompletableFuture()
                    .thenComposeAsync(responses -> {
                        List<CompletableFuture<String>> promiseArrRequests = new ArrayList<>();
                        List<String> nodeSigs = new ArrayList<>();
                        for (String respons : responses) {
                            if (respons != null && !respons.equals("")) {
                                Gson gson = new Gson();
                                JsonRPCResponse nodeSigResponse = gson.fromJson(respons, JsonRPCResponse.class);
                                if (nodeSigResponse != null && nodeSigResponse.getResult() != null) {
                                    nodeSigs.add(gson.toJson(nodeSigResponse.getResult()));
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
                            String req = APIUtils.generateJsonRPCObject("ShareRequest", new ShareRequestParams(shareRequestItems));
                            promiseArrRequests.add(APIUtils.post(endpoint, req, false));
                        }
                        return new Some<>(promiseArrRequests, (shareResponses, predicateResolved) -> {
                            // check if threshold number of nodes have returned the same user public key
                            BigInteger privateKey = null;
                            List<String> completedResponses = new ArrayList<>();
                            Gson gson = new Gson();
                            for (String shareResponse : shareResponses) {
                                if (shareResponse != null && !shareResponse.equals("")) {
                                    JsonRPCResponse shareResponseJson = gson.fromJson(shareResponse, JsonRPCResponse.class);
                                    if (shareResponseJson != null && shareResponseJson.getResult() != null) {
                                        completedResponses.add(gson.toJson(shareResponseJson.getResult()));
                                    }
                                }
                            }
                            List<String> completedResponsesPubKeys = new ArrayList<>();
                            for (String x :
                                    completedResponses) {
                                KeyAssignResult keyAssignResult = gson.fromJson(x, KeyAssignResult.class);
                                if (keyAssignResult == null || keyAssignResult.getKeys() == null || keyAssignResult.getKeys().length == 0) {
                                    return null;
                                }
                                KeyAssignment keyAssignResultFirstKey = keyAssignResult.getKeys()[0];
                                completedResponsesPubKeys.add(gson.toJson(keyAssignResultFirstKey.getPublicKey()));
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
                                        JsonRPCResponse currentJsonRPCResponse = gson.fromJson(shareResponses[i], JsonRPCResponse.class);
                                        if (currentJsonRPCResponse != null && currentJsonRPCResponse.getResult() != null && !currentJsonRPCResponse.getResult().equals("")) {
                                            KeyAssignResult currentShareResponse = gson.fromJson(gson.toJson(currentJsonRPCResponse.getResult()), KeyAssignResult.class);
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
                                    }
                                }
                                if (predicateResolved.get())
                                    return null;
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
                                    BigInteger derivedPrivateKey = this.lagrangeInterpolation(currentCombiSharesValues.toArray(new BigInteger[0]),
                                            currentCombiSharesIndexes.toArray(new BigInteger[0]));
                                    assert derivedPrivateKey != null;
                                    ECKeyPair derivedECKeyPair = ECKeyPair.create(derivedPrivateKey);
                                    String derivedPubKeyString = derivedECKeyPair.getPublicKey().toString(16);
                                    String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2);
                                    String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);
                                    if (new BigInteger(derivedPubKeyX, 16).compareTo(new BigInteger(thresholdPubKey.getX(), 16)) == 0 &&
                                            new BigInteger(derivedPubKeyY, 16).compareTo(new BigInteger(thresholdPubKey.getY(), 16)) == 0
                                    ) {
                                        privateKey = derivedPrivateKey;
                                        break;
                                    }
                                }
                                if (privateKey == null) {
                                    throw new PredicateFailedException("could not derive private key");
                                }
                                return CompletableFuture.completedFuture(privateKey);
                            } else {
                                throw new PredicateFailedException("could not get enough shares");
                            }
                        }).getCompletableFuture();
                    }).thenComposeAsync((privateKey) -> {
                        ECKeyPair derivedECKeyPair = ECKeyPair.create(privateKey);
                        String derivedPubKeyString = derivedECKeyPair.getPublicKey().toString(16);
                        String derivedPubKeyX = derivedPubKeyString.substring(0, derivedPubKeyString.length() / 2);
                        String derivedPubKeyY = derivedPubKeyString.substring(derivedPubKeyString.length() / 2);
                        BigInteger metadataNonce = this.getMetadata(new MetadataPubKey(derivedPubKeyX, derivedPubKeyY)).join();
                        privateKey = privateKey.add(metadataNonce).mod(secp256k1N);
                        String ethAddress = this.generateAddressFromPrivKey(privateKey.toString(16));
                        return CompletableFuture.completedFuture(new RetrieveSharesResponse(ethAddress, privateKey.toString(16)));
                    });
        } catch (Exception e) {
            e.printStackTrace();
            throw new TorusException("Torus Internal Error", e);
        }
    }

    public CompletableFuture<RetrieveSharesResponse> retrieveShares(String[] endpoints, BigInteger[] indexes, String verifier,
                                                                    HashMap<String, Object> verifierParams, String idToken) throws TorusException {
        return this.retrieveShares(endpoints, indexes, verifier, verifierParams, idToken, null);
    }

    public CompletableFuture<BigInteger> getMetadata(MetadataPubKey data) {
        try {
            Gson gson = new Gson();
            String metadata = gson.toJson(data, MetadataPubKey.class);
            String metadataApiResponse = APIUtils.post(this.metadataHost + "/get", metadata, true).join();
            MetadataResponse response = gson.fromJson(metadataApiResponse, MetadataResponse.class);
            BigInteger finalResponse = Utils.isEmpty(response.getMessage()) ? new BigInteger("0") : new BigInteger(response.getMessage(), 16);
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

    CompletableFuture<TorusPublicKey> _getPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs, boolean isExtended) {
        CompletableFuture<TorusPublicKey> completableFuture = new CompletableFuture<>();
        Utils.keyLookup(endpoints, verifierArgs.getVerifier(), verifierArgs.getVerifierId())
                .thenComposeAsync(keyLookupResult -> {
                    if (keyLookupResult.getErrResult() != null && keyLookupResult.getErrResult().contains("Verifier + VerifierID has not yet been assigned")) {
                        return Utils
                                .keyAssign(endpoints, torusNodePubs, null, null, verifierArgs.getVerifier(), verifierArgs.getVerifierId())
                                .thenComposeAsync(k -> Utils.waitKeyLookup(endpoints, verifierArgs.getVerifier(), verifierArgs.getVerifierId(), 1000))
                                .thenComposeAsync(res -> {
                                    if (res == null || res.getKeyResult() == null) {
                                        completableFuture.completeExceptionally(new Exception("could not get lookup, no results"));
                                        return null;
                                    }
                                    Gson gson = new Gson();
                                    VerifierLookupRequestResult verifierLookupRequestResult = gson.fromJson(res.getKeyResult(), VerifierLookupRequestResult.class);
                                    if (verifierLookupRequestResult == null || verifierLookupRequestResult.getKeys() == null || verifierLookupRequestResult.getKeys().length == 0) {
                                        completableFuture.completeExceptionally(new Exception("could not get lookup, no keys"));
                                        return null;
                                    }
                                    VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                                    return CompletableFuture.completedFuture(verifierLookupItem);
                                });
                    }
                    if (keyLookupResult.getKeyResult() != null) {
                        Gson gson = new Gson();
                        VerifierLookupRequestResult verifierLookupRequestResult = gson.fromJson(keyLookupResult.getKeyResult(), VerifierLookupRequestResult.class);
                        if (verifierLookupRequestResult == null || verifierLookupRequestResult.getKeys() == null || verifierLookupRequestResult.getKeys().length == 0) {
                            completableFuture.completeExceptionally(new Exception("could not get lookup, no keys"));
                            return null;
                        }
                        VerifierLookupItem verifierLookupItem = verifierLookupRequestResult.getKeys()[0];
                        return CompletableFuture.completedFuture(verifierLookupItem);
                    }
                    completableFuture.completeExceptionally(new Exception("could not get lookup, no valid key result or error result"));
                    return null;
                }).thenComposeAsync(verifierLookupItem -> {
                    if (verifierLookupItem == null) {
                        completableFuture.completeExceptionally(new Exception("node results do not match"));
                        return null;
                    }
                    BigInteger metadataNonce = this.getMetadata(new MetadataPubKey(verifierLookupItem.getPub_key_X(), verifierLookupItem.getPub_key_Y())).join();
                    //            String pubKey = Utils.padLeft(verifierLookupItem.getPub_key_X(), '0', 64) + Utils.padLeft(verifierLookupItem.getPub_key_Y(), '0', 64);

                    // curve point addition
                    ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
                    ECPoint metadataPoint = curve.getG().multiply(metadataNonce);
                    ECPoint rawPoint = curve.getCurve().createPoint(new BigInteger(verifierLookupItem.getPub_key_X(), 16), new BigInteger(verifierLookupItem.getPub_key_Y(), 16));
                    ECPoint finalPoint = rawPoint.add(metadataPoint).normalize();
                    String finalPubKey = Utils.padLeft(finalPoint.getAffineXCoord().toString(), '0', 64) + Utils.padLeft(finalPoint.getAffineYCoord().toString(), '0', 64);

                    String address = Keys.toChecksumAddress(Hash.sha3(finalPubKey).substring(64 - 38));
                    if (!isExtended) {
                        completableFuture.complete(new TorusPublicKey(address));
                    } else {
                        completableFuture.complete(new TorusPublicKey(finalPubKey.substring(0, finalPubKey.length() / 2), finalPubKey.substring(finalPubKey.length() / 2),
                                address));
                    }
                    return null;
                }).exceptionally(completableFuture::completeExceptionally);
        return completableFuture;
    }

    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs, boolean isExtended) {
        return _getPublicAddress(endpoints, torusNodePubs, verifierArgs, isExtended);
    }

    public CompletableFuture<TorusPublicKey> getPublicAddress(String[] endpoints, TorusNodePub[] torusNodePubs, VerifierArgs verifierArgs) {
        return _getPublicAddress(endpoints, torusNodePubs, verifierArgs, false);
    }
}
