package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.TorusUtils.secp256k1N;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.KeyLookupResult;
import org.torusresearch.torusutils.apis.KeyResult;
import org.torusresearch.torusutils.apis.requests.GetNonceParams;
import org.torusresearch.torusutils.apis.requests.GetNonceSetDataParams;
import org.torusresearch.torusutils.apis.requests.GetOrSetKeyParams;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.apis.responses.PubNonce;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierKey;
import org.torusresearch.torusutils.apis.responses.VerifierLookupResponse.VerifierLookupResponse;
import org.torusresearch.torusutils.types.JRPCResponse;
import org.torusresearch.torusutils.types.MetadataParams;
import org.torusresearch.torusutils.types.SetData;
import org.torusresearch.torusutils.types.TorusKeyType;
import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.Polynomial;
import org.torusresearch.torusutils.types.Share;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

public class Utils {
    private Utils() {
    }

    public static double trunc(double value) {
        return value<0 ? Math.ceil(value) : Math.floor(value);
    }

    // TODO: Check this, write tests
    public static <T> T thresholdSame(T[] arr, int threshold) throws JsonProcessingException {
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

    public static String thresholdSame(List<String> list, int threshold) throws JsonProcessingException {
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

    public static boolean isLegacyNetorkRouteMap(Web3AuthNetwork network) {
        // TODO: Fix this in fetchnodedetails, comparison should be against .legacy(network)
        return !network.name().toLowerCase().contains("sapphire");
    }
    public static KeyResult normalizeKeyResult(VerifierLookupResponse result) {
        Boolean isNewKey = false;
        if (result.is_new_key != null) {
            isNewKey = result.is_new_key;
        }
        KeyResult finalResult = new KeyResult(isNewKey);
        if (result.keys.length > 0) {
            VerifierKey finalKey = result.keys[0];
            finalResult.keys = new VerifierKey[]{ finalKey };
        }
        return finalResult;
    }

    public static MetadataParams generateMetadataParams(@NotNull Integer serverTimeOffset, @NotNull String message, @NotNull String privateKey, @NotNull String X, @NotNull String Y, @Nullable TorusKeyType keyType) throws Exception {
        int timeStamp = serverTimeOffset + (int) (System.currentTimeMillis() / 1000L);
        SetData setData = new SetData(message, String.valueOf(timeStamp));
        PrivateKey key = KeyUtils.deserializePrivateKey(Hex.decode(privateKey));

        Gson gson = new Gson();
        String setDataString = gson.toJson(setData);
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
        ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(new BigInteger(KeyUtils.serializePrivateKey(key)), domainParams);
        byte[] hashedData = Hash.sha3(setDataString.getBytes(StandardCharsets.UTF_8));
        SecureRandom random = new SecureRandom();
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, new ParametersWithRandom(privKeyParams, random));
        BigInteger[] signature = signer.generateSignature(hashedData);

        String sig = Utils.padLeft(signature[0].toString(16), '0', 64) + Utils.padLeft(signature[1].toString(16), '0', 64) + Utils.padLeft("", '0', 2);
        byte[] sigBytes = java.util.Base64.getEncoder().encode(Hex.decode(sig));
        String finalSig = new String(sigBytes, StandardCharsets.UTF_8);
        return new MetadataParams(X, Y, setData, finalSig, null, keyType);
    }

    public static GetOrSetNonceResult getOrSetNonce(@NotNull String legacyMetadataHost, @NotNull String X, @NotNull String Y, @NotNull Integer serverTimeOffset, @Nullable String privateKey, Boolean getOnly, @Nullable TorusKeyType keyType) throws Exception {
        String msg = getOnly ? "getNonce": "getOrSetNonce";
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        String data;
        if (privateKey != null) {
            MetadataParams params = generateMetadataParams(serverTimeOffset, msg, privateKey, X, Y, keyType);
            data = gson.toJson(params);
        } else {
            GetNonceParams params = new GetNonceParams(X, Y , new GetNonceSetDataParams(msg));
            data = gson.toJson(params);
        }

        String postResult = APIUtils.post(legacyMetadataHost + "/get_or_set_nonce", data, true).get();
        JSONObject jsonObject = new JSONObject(postResult);
        return gson.fromJson(jsonObject.toString(), GetOrSetNonceResult.class);
    }

    public static GetOrSetNonceResult getOrSetSapphireMetadataNonce(@NotNull String metadataHost, @NotNull Web3AuthNetwork network, @NotNull String X, @NotNull String Y, @Nullable Integer serverTimeOffset, @Nullable String privateKey, Boolean getOnly, @Nullable TorusKeyType keyType) throws Exception {
        // fix this comparision in fetchnodedetails, comparision should be against .sapphire()
        int timeOffset = 0;
        if (serverTimeOffset != null) {
            timeOffset = serverTimeOffset;
        }

        timeOffset += (int) (System.currentTimeMillis() / 1000);

        if (network.name().contains("sapphire")) {
            return getOrSetNonce(metadataHost, X, Y, timeOffset, privateKey, getOnly, keyType);
        } else {
            throw TorusUtilError.METADATA_NONCE_MISSING;
        }
    }

    /*
    public static int getTimeDiff(BigInteger timestampInSeconds) {
        BigInteger timestampInMillis = timestampInSeconds.multiply(BigInteger.valueOf(1000));
        BigInteger systemTimestampMillis = BigInteger.valueOf(System.currentTimeMillis());
        BigInteger timeDifferenceMillis = systemTimestampMillis.subtract(timestampInMillis);
        BigInteger timeDifferenceSeconds = timeDifferenceMillis.divide(BigInteger.valueOf(1000));
        //System.out.println("Time difference: " + timeDifferenceSeconds + " seconds");
        return timeDifferenceSeconds.intValue();
    }
     */
    public static KeyLookupResult getPubKeyOrKeyAssign(@NotNull  String[] endpoints, @NotNull  Web3AuthNetwork network, @NotNull String verifier, @NotNull String verifierId, @NotNull String legacyMetdadataHost, @Nullable Integer serverTimeOffset, @Nullable String extendedVerifierId) throws Exception {
        int threshold = (endpoints.length / 2) + 1;

        BigInteger timeOffset = BigInteger.ZERO;
        if (serverTimeOffset != null) {
            timeOffset = BigInteger.valueOf(serverTimeOffset);
        }
        timeOffset.add( new BigInteger(String.valueOf(System.currentTimeMillis() / 1000)));

        GetOrSetKeyParams params = new GetOrSetKeyParams(true, verifier, verifierId, extendedVerifierId, true, true, timeOffset.toString());
        List<CompletableFuture<String>> lookupPromises = new ArrayList<>();
        for (int i = 0; i < endpoints.length; i++) {
            lookupPromises.add(i, APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("GetPubKeyOrKeyAssign",
                    params), false));
        }

        ArrayList<JsonRPCResponse<VerifierLookupResponse>> collected = new ArrayList<>();

        JRPCResponse.ErrorInfo errResult = null;
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
                lookupPubKeys = collected.stream().filter(item -> item.getError() == null && item.getResult() != null).collect(Collectors.toList());
                errResult = (JRPCResponse.ErrorInfo) Utils.thresholdSame(collected.stream().filter(item -> item.getError() != null).toArray(), threshold);
                ArrayList<KeyResult> normalizedKeys = new ArrayList<>();
                for (JsonRPCResponse<VerifierLookupResponse> item : lookupPubKeys) {
                    VerifierLookupResponse vlr = item.getTypedResult(VerifierLookupResponse.class);
                    normalizedKeys.add(normalizeKeyResult(vlr));
                }
                key = (KeyResult) Utils.thresholdSame(normalizedKeys.toArray(), threshold);
                if (key != null) {
                    break;
                }
            } catch (Exception e) {
                collected.add(null);
            }
        }

        if (key != null && nonce == null && extendedVerifierId == null && !isLegacyNetorkRouteMap(network)) {
            for (int i = 0; i < lookupPubKeys.size(); i++) {
                JsonRPCResponse<VerifierLookupResponse> x1 = lookupPubKeys.get(i);
                if (x1 != null && x1.getError() == null) {
                    VerifierLookupResponse x1Result = x1.getTypedResult(VerifierLookupResponse.class);
                   String currentNodePubKeyX = Utils.addLeading0sForLength64(x1Result.keys[0].pub_key_X).toLowerCase();
                   String thresholdPubKeyX = Utils.addLeading0sForLength64(key.keys[0].pub_key_X).toLowerCase();
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
               nonce = getOrSetSapphireMetadataNonce(legacyMetdadataHost, network, key.keys[0].pub_key_X,key.keys[0].pub_key_Y, null, null, false, null);
               if (nonce.nonce != null) {
                   nonce.nonce = null;
               }
            }
        }

        ArrayList<Integer> serverTimeOffsets = new ArrayList<>();
        ArrayList<Integer> nodeIndexes = new ArrayList<>();
        if (key != null && (nonce != null || extendedVerifierId != null || isLegacyNetorkRouteMap(network) || errResult != null)) {
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
            finalServerTimeOffset = calculateMedian(serverTimeOffsets);
        }
        return new KeyLookupResult(key,nodeIndexes, finalServerTimeOffset, nonce, errResult);
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

    public static Integer calculateMedian(List<Integer> arr) {
        int arrSize = arr.size();

        if (arrSize == 0) return 0;

        Collections.sort(arr);

        // odd length
        if (arrSize % 2 != 0) {
            return arr.get(arrSize / 2);
        }

        // return average of two mid values in case of even arrSize
        Integer mid1 = arr.get(arrSize / 2 - 1);
        Integer mid2 = arr.get(arrSize / 2);
        return (mid1+mid2)/2;
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
