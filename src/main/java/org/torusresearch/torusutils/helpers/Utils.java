package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.TorusUtils.secp256k1N;

import com.google.gson.Gson;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
import org.json.JSONObject;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.GetPubKeyOrKeyAssignRequestParams;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.KeyLookupResult;
import org.torusresearch.torusutils.apis.KeyResult;
import org.torusresearch.torusutils.apis.KeysRPCResponse;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.PubNonce;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierLookupResponse;
import org.torusresearch.torusutils.types.JRPCResponse;
import org.torusresearch.torusutils.types.TorusKeyType;
import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.Polynomial;
import org.torusresearch.torusutils.types.Share;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class Utils {
    private Utils() {
    }

    // TODO: Check this, write tests
    public static <T> T thresholdSame(T[] arr, int threshold) {
        HashMap<T, Integer> hashMap = new HashMap<>();
        for (T s : arr) {
            Integer currentCount = hashMap.get(s);
            if (currentCount == null) currentCount = 0;
            int incrementedCount = currentCount + 1;
            if (incrementedCount == threshold) {
                return s;
            }
            hashMap.put(s, currentCount + 1);
        }
        return null;
    }

    public static String thresholdSame(List<String> list, int threshold) {
        String[] arr = new String[list.size()];
        list.toArray(arr);
        return Utils.thresholdSame(arr, threshold);
    }

    public static List<List<Integer>> kCombinations(int s, int k) {
        List<Integer> set = new ArrayList<>();
        for (int i = 0; i < s; i++) {
            set.add(i);
        }
        return kCombinations(set, k);
    }

    public static List<List<Integer>> kCombinations(List<Integer> set, int k) {
        List<List<Integer>> combs = new ArrayList<>();

        if ((k == 0) || k > set.size())
        {
            return combs;
        }

        if (k == set.size()) {
            combs.add(set);
            return combs;
        }

        if (k == 1) {
            for (Integer i : set) {
                ArrayList<Integer> arrList = new ArrayList<>();
                arrList.add(i);
                combs.add(arrList);
            }
            return combs;
        }

        for (int i = 0; i < ((set.size() - k) + 1); i++) {
            List<List<Integer>> tailCombs = Utils.kCombinations(set.subList(i + 1, set.size()), k - 1);
            for (List<Integer> tailComb : tailCombs) {
                List<Integer> prependedComb = new ArrayList<>();
                prependedComb.add(set.get(i));
                prependedComb.addAll(tailComb);
                combs.add(prependedComb);
            }
        }
        return combs;
    }

    public static CompletableFuture<KeyLookupResult> getPubKeyOrKeyAssign(String[] endpoints, String network, String verifier, String verifierId, TorusKeyType keyType, String extendedVerifierId) {
        int k = endpoints.length / 2 + 1;
        List<CompletableFuture<String>> lookupPromises = new ArrayList<>();
        for (int i = 0; i < endpoints.length; i++) {
            lookupPromises.add(i, APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("GetPubKeyOrKeyAssign",
                    new GetPubKeyOrKeyAssignRequestParams(verifier, verifierId, extendedVerifierId, keyType,
                            true, true, true)), false));
        }
        return new Some<>(lookupPromises, (lookupResults, resolved) -> {
            try {
                List<JRPCResponse.ErrorInfo> errorResults = new ArrayList<>();
                List<String> keyResults = new ArrayList<>();
                List<BigInteger> nodeIndexes = new ArrayList<>();
                GetOrSetNonceResult nonceResult = null;
                Gson gson = new Gson();
                for (String x : lookupResults) {
                    if (x != null && !x.equals("")) {
                        try {
                            JsonRPCResponse response = gson.fromJson(x, JsonRPCResponse.class);
                            JSONObject jsonObject = new JSONObject(Utils.convertToJsonObject(response.getResult()));
                            if (jsonObject.has("node_index")) {
                                jsonObject.remove("node_index");
                            }
                            if (jsonObject.has("keys")) {
                                JSONArray keysArray = (JSONArray) jsonObject.get("keys");
                                for (int i = 0; i < keysArray.length(); i++) {
                                    JSONObject keyObject = (JSONObject) keysArray.get(i);
                                    if (keyObject.has("key_index")) {
                                        keyObject.remove("key_index");
                                    }
                                    if (keyObject.has("created_at")) {
                                        keyObject.remove("created_at");
                                    }
                                }
                            }
                            keyResults.add(jsonObject.toString());
                        } catch (Exception e) {
                            keyResults.add("");
                        }
                    }
                }
                for (String x : lookupResults) {
                    if (x != null && !x.equals("")) {
                        try {
                            JsonRPCResponse response = gson.fromJson(x, JsonRPCResponse.class);
                            errorResults.add((JRPCResponse.ErrorInfo) response.getResult());
                        } catch (Exception e) {
                            errorResults.add(null);
                        }
                    }
                }
                for (String x : lookupResults) {
                    if (x != null && !x.equals("")) {
                        try {
                            JsonRPCResponse response = gson.fromJson(x, JsonRPCResponse.class);
                            VerifierLookupResponse verifierLookupResponse = gson.fromJson(Utils.convertToJsonObject(response.getResult()), VerifierLookupResponse.class);
                            String pubNonceX = null;
                            PubNonce pubNonce = verifierLookupResponse.keys[0].nonce_data.pubNonce;
                            if (pubNonce != null) {
                                pubNonceX = pubNonce.x;
                            }
                            if (pubNonceX != null) {
                                nonceResult = verifierLookupResponse.keys[0].nonce_data;
                            }
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                }

                JRPCResponse.ErrorInfo errorResult = (JRPCResponse.ErrorInfo) thresholdSame(errorResults.toArray(), k);
                KeyResult keyResult = (KeyResult) thresholdSame(keyResults.toArray(), k);

                if (keyResult != null && nonceResult == null && extendedVerifierId == null && !org.torusresearch.fetchnodedetails.types.Utils.LEGACY_NETWORKS_ROUTE_MAP.containsKey(network)) {
                    for (String x1 : lookupResults) {
                        if (x1 != null && !x1.equals("")) {
                            JsonRPCResponse response = gson.fromJson(x1, JsonRPCResponse.class);
                            VerifierLookupResponse verifierLookupResponse = gson.fromJson(Utils.convertToJsonObject(response.getResult()), VerifierLookupResponse.class);
                            String currentNodePubKey = verifierLookupResponse.keys[0].pub_key_X.toLowerCase();
                            // Possible NullPointerException here
                            PubNonce pubNonce = verifierLookupResponse.keys[0].nonce_data.pubNonce;
                            String pubNonceX = null;
                            if (pubNonce != null)
                            {
                                pubNonceX = pubNonce.x;
                            }

                            String thresholdPubKey = null;
                            for (String x : keyResults) {
                                KeysRPCResponse keyResponse = gson.fromJson(x, KeysRPCResponse.class);
                                thresholdPubKey = keyResponse.getKeys().get(0).getPubKeyX().toLowerCase();
                            }
                            if (pubNonceX != null && currentNodePubKey.equals(thresholdPubKey)) {
                                nonceResult = verifierLookupResponse.keys[0].nonce_data;
                                break;
                            }
                        }
                    }
                }

                List<BigInteger> serverTimeOffsets = new ArrayList<>();
                if ((keyResult != null && (nonceResult != null || extendedVerifierId != null || org.torusresearch.fetchnodedetails.types.Utils.LEGACY_NETWORKS_ROUTE_MAP.containsKey(network)))
                        || errorResult != null) {
                    for (String x : lookupResults) {
                        JsonRPCResponse response = gson.fromJson(x, JsonRPCResponse.class);
                        VerifierLookupResponse verifierLookupResponse = gson.fromJson(Utils.convertToJsonObject(response.getResult()), VerifierLookupResponse.class);
                        String currentNodePubKey = verifierLookupResponse.keys[0].pub_key_X.toLowerCase();
                        String serverTimeOffsetStr = verifierLookupResponse.server_time_offset;
                        String thresholdPubKey = null;
                        for (String x1 : keyResults) {
                            KeysRPCResponse keyResponse = gson.fromJson(x1, KeysRPCResponse.class);
                            thresholdPubKey = keyResponse.getKeys().get(0).getPubKeyX().toLowerCase();
                        }
                        if (currentNodePubKey.equals(thresholdPubKey)) {
                            nodeIndexes.add(new BigInteger(verifierLookupResponse.node_index, 16));
                        }
                        BigInteger serverTimeOffset = BigInteger.valueOf(serverTimeOffsetStr != null ? Integer.parseInt(serverTimeOffsetStr, 10) : 0);
                        serverTimeOffsets.add(serverTimeOffset);
                    }
                    BigInteger serverTimeOffset = keyResult != null ? (BigInteger) calculateMedian(serverTimeOffsets) : BigInteger.ZERO;
                    return CompletableFuture.completedFuture(new KeyLookupResult(keyResult, nodeIndexes, serverTimeOffset, nonceResult,  errorResult));
                }

                CompletableFuture<KeyLookupResult> failedFuture = new CompletableFuture<>();
                failedFuture.completeExceptionally(new Exception("invalid results from KeyLookup " + gson.toJson(lookupResults)));
                return failedFuture;
            } catch (Exception e) {
                return null;
            }
        }).getCompletableFuture();
    }

    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.length() == 0;
    }

    public static String padLeft(String inputString, Character padChar, int length) {
        if (inputString.length() >= length) return inputString;
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append(padChar);
        }
        sb.append(inputString);
        return sb.toString();
    }

    public static String convertToJsonObject(Object obj) {
        Gson gson = new Gson();
        return obj == null ? "" : gson.toJson(obj);
    }

    public static ECPoint getPublicKeyFromHex(String X, String Y) {
        BigInteger x = new BigInteger(X, 16);
        BigInteger y = new BigInteger(Y, 16);
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
        return curve.getCurve().createPoint(x, y);
    }

    public static boolean isSapphireNetwork(String network) {
        return network.contains("sapphire");
    }

    public static String getPrivKey(String sessionId) {
        ECKeyPair derivedECKeyPair = ECKeyPair.create(new BigInteger(sessionId, 16));
        return derivedECKeyPair.getPrivateKey().toString(16);
    }

    public static BigInteger generatePrivate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return Keys.createEcKeyPair().getPrivateKey();
    }

    public static Polynomial generateRandomPolynomial(int degree, BigInteger secret, @Nullable List<Share> deterministicShares) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        BigInteger actualS = secret;
        if (secret == null) {
            actualS = generatePrivateExcludingIndexes(getBigIntegerList());
        }
        if (deterministicShares == null) {
            List<BigInteger> poly = new ArrayList<>();
            poly.add(actualS);
            for (int i = 0; i < degree; i++) {
                BigInteger share = generatePrivateExcludingIndexes(poly);
                poly.add(share);
            }
            return new Polynomial(poly.toArray(new BigInteger[0]));
        }

        if (deterministicShares.size() > degree) {
            throw new Error("deterministicShares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness");
        }
        Map<String, Point> points = new HashMap<>();
        for (Share share : deterministicShares) {
            points.put(share.getShareIndex().toString(), new Point(share.getShareIndex(), share.getShare()));
        }
        for (int i = 0; i < degree - deterministicShares.size(); i++) {
            BigInteger shareIndex = generatePrivateExcludingIndexes(getBigIntegerList());
            while (points.containsKey(shareIndex.toString(16))) {
                shareIndex = generatePrivateExcludingIndexes(getBigIntegerList());
            }
            points.put(shareIndex.toString(16), new Point(shareIndex, generatePrivate()));
        }
        points.put("0", new Point(BigInteger.ZERO, actualS));
        return lagrangeInterpolatePolynomial(new ArrayList<>(points.values()));
    }

    public static List<BigInteger> getBigIntegerList() {
        List<BigInteger> bigIntegersList = new ArrayList<>();

        for (int i = 0; i < 1; i++) {
            bigIntegersList.add(BigInteger.ZERO);
        }
        return bigIntegersList;
    }

    public static Polynomial lagrangeInterpolatePolynomial(List<Point> points) {
        return lagrange(points);
    }

    private static Polynomial lagrange(List<Point> unsortedPoints) {
        List<Point> sortedPoints = pointSort(unsortedPoints);
        BigInteger[] polynomial = generateEmptyBNArray(sortedPoints.size());
        for (int i = 0; i < sortedPoints.size(); i++) {
            BigInteger[] coefficients = interpolationPoly(i, sortedPoints);
            for (int k = 0; k < sortedPoints.size(); k++) {
                BigInteger tmp = sortedPoints.get(i).getY();
                tmp = tmp.multiply(coefficients[k]);
                polynomial[k] = polynomial[k].add(tmp).mod(secp256k1N);
            }
        }
        return new Polynomial(polynomial);
    }

    private static BigInteger[] interpolationPoly(int i, List<Point> innerPoints) {
        BigInteger[] coefficients = generateEmptyBNArray(innerPoints.size());
        BigInteger d = denominator(i, innerPoints);
        if (d.compareTo(BigInteger.ZERO) == 0) {
            throw new ArithmeticException("Denominator for interpolationPoly is 0");
        }
        coefficients[0] = d.modInverse(secp256k1N);
        for (int k = 0; k < innerPoints.size(); k++) {
            BigInteger[] newCoefficients = generateEmptyBNArray(innerPoints.size());
            if (k != i) {
                int j;
                if (k < i) {
                    j = k + 1;
                } else {
                    j = k;
                }
                j--;
                for (; j >= 0; j--) {
                    newCoefficients[j + 1] = newCoefficients[j + 1].add(coefficients[j]).mod(secp256k1N);
                    BigInteger tmp = innerPoints.get(k).getX();
                    tmp = tmp.multiply(coefficients[j]).mod(secp256k1N);
                    newCoefficients[j] = newCoefficients[j].subtract(tmp).mod(secp256k1N);
                }
                coefficients = newCoefficients;
            }
        }
        return coefficients;
    }

    private static BigInteger denominator(int i, List<Point> innerPoints) {
        BigInteger result = BigInteger.ONE;
        BigInteger xi = innerPoints.get(i).getX();
        for (int j = innerPoints.size() - 1; j >= 0; j--) {
            if (i != j) {
                BigInteger tmp = xi.subtract(innerPoints.get(j).getX());
                tmp = tmp.mod(secp256k1N);
                result = result.multiply(tmp).mod(secp256k1N);
            }
        }
        return result;
    }

    private static List<Point> pointSort(List<Point> innerPoints) {
        List<Point> pointArrClone = new ArrayList<>(innerPoints);
        pointArrClone.sort(Comparator.comparing(Point::getX));
        return pointArrClone;
    }

    private static BigInteger[] generateEmptyBNArray(int length) {
        BigInteger[] array = new BigInteger[length];
        for (int i = 0; i < length; i++) {
            array[i] = BigInteger.ZERO;
        }
        return array;
    }

    private static BigInteger generatePrivateExcludingIndexes(List<BigInteger> shareIndexes) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        BigInteger key = Keys.createEcKeyPair().getPrivateKey();
        for (BigInteger el : shareIndexes) {
            if (el.equals(key)) {
                return generatePrivateExcludingIndexes(shareIndexes);
            }
        }
        return key;
    }

    public static BigInteger calculateMedian(List<BigInteger> arr) {
        int arrSize = arr.size();

        if (arrSize == 0) return BigInteger.ZERO;

        Collections.sort(arr);

        // odd length
        if (arrSize % 2 != 0) {
            return arr.get(arrSize / 2);
        }

        // return average of two mid values in case of even arrSize
        BigInteger mid1 = arr.get(arrSize / 2 - 1);
        BigInteger mid2 = arr.get(arrSize / 2);
        return (mid1.add(mid2)).divide(BigInteger.valueOf(2));
    }

    public static String addLeading0sForLength64(String input) {
        StringBuilder inputBuilder = new StringBuilder(input);
        while (inputBuilder.length() < 64) {
            inputBuilder.insert(0, "0");
        }
        input = inputBuilder.toString();
        return input;
    }

    public static String addLeadingZerosForLength64(String input) {
        int targetLength = 64;
        int inputLength = input.length();

        if (inputLength >= targetLength) {
            return input;
        } else {
            int numberOfZeros = targetLength - inputLength;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < numberOfZeros; i++) {
                sb.append('0');
            }
            sb.append(input);
            return sb.toString();
        }
    }

    public static String serializeHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static String strip04Prefix(String pubKey) {
        if (pubKey.startsWith("04")) {
            return pubKey.substring(2);
        }
        return pubKey;
    }

    public static int getProxyCoordinatorEndpointIndex(String[] endpoints, String verifier, String verifierId) {
        String verifierIdString = verifier + verifierId;
        String hashedVerifierId = Hash.sha3(verifierIdString).replace("0x", "");
        BigInteger proxyEndPointNum = new BigInteger(hashedVerifierId, 16).mod(BigInteger.valueOf(endpoints.length));
        return proxyEndPointNum.intValue();
    }

    public static byte[] toByteArray(BigInteger bi) {
        byte[] b = bi.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            int n = b.length - 1;
            byte[] newArray = new byte[n];
            System.arraycopy(b, 1, newArray, 0, n);
            b = newArray;
        }
        return b;
    }
}
