package org.torusresearch.torusutils.helpers;

import com.google.gson.Gson;

import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.KeyAssignParams;
import org.torusresearch.torusutils.apis.KeyLookupResult;
import org.torusresearch.torusutils.apis.SignerResponse;
import org.torusresearch.torusutils.apis.VerifierLookupRequestParams;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

import java8.util.concurrent.CompletableFuture;
import okhttp3.internal.http2.Header;

public class Utils {
    private Utils() {
    }

    public static String thresholdSame(String[] arr, int threshold) {
        HashMap<String, Integer> hashMap = new HashMap<>();
        for (String s : arr) {
            Integer currentCount = hashMap.getOrDefault(s, 0);
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
        if (k > set.size()) {
            return combs;
        }
        if (k == set.size()) {
            combs.add(set);
            return combs;
        }
        if (k == 1) {
            for (Integer i :
                    set) {
                ArrayList<Integer> arrList = new ArrayList<>();
                arrList.add(i);
                combs.add(arrList);
            }
            return combs;
        }
        for (int i = 0; i < set.size() - k + 1; i++) {
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

    public static CompletableFuture<KeyLookupResult> keyLookup(String[] endpoints, String verifier, String verifierId) {
        int k = Math.floorDiv(endpoints.length, 2) + 1;
        List<CompletableFuture<String>> lookupPromises = new ArrayList<>();
        for (int i = 0; i < endpoints.length; i++) {
            lookupPromises.add(i, APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("VerifierLookupRequest", new VerifierLookupRequestParams(verifier, verifierId)), false));
        }
        return new Some<>(lookupPromises, (lookupResults, resolved) -> {
            try {
                List<String> errorResults = new ArrayList<>();
                List<String> keyResults = new ArrayList<>();
                Gson gson = new Gson();
                for (String x :
                        lookupResults) {
                    if (!x.equals("")) {
                        try {
                            JsonRPCResponse response = gson.fromJson(x, JsonRPCResponse.class);
                            keyResults.add(gson.toJson(response.getResult()));
                        } catch (Exception e) {
                            keyResults.add("");
                        }
                    }
                }
                for (String x :
                        lookupResults) {
                    if (!x.equals("")) {
                        try {
                            JsonRPCResponse response = gson.fromJson(x, JsonRPCResponse.class);
                            errorResults.add(response.getError().getData());
                        } catch (Exception e) {
                            errorResults.add("");
                        }
                    }
                }
                String errorResult = thresholdSame(errorResults, k);
                String keyResult = thresholdSame(keyResults, k);
                if (!errorResult.equals("") || !keyResult.equals("")) {
                    return CompletableFuture.completedFuture(new KeyLookupResult(keyResult, errorResult));
                }
                CompletableFuture<KeyLookupResult> failedFuture = new CompletableFuture<>();
                failedFuture.completeExceptionally(new Exception("invalid "));
                return failedFuture;
            } catch (Exception e) {
                return null;
            }
        }).getCompletableFuture();
    }

    public static CompletableFuture<KeyLookupResult> keyAssign(String[] endpoints, TorusNodePub[] torusNodePubs, Integer lastPoint, Integer firstPoint, String verifier, String verifierId) {
        Integer nodeNum, initialPoint = null;
        CompletableFuture<KeyLookupResult> completableFuture = new CompletableFuture<>();

        if (lastPoint == null) {
            nodeNum = new Random().nextInt(endpoints.length);
            initialPoint = nodeNum;
        } else {
            nodeNum = Math.floorMod(lastPoint, endpoints.length);
        }
        if (nodeNum.equals(firstPoint)) {
            completableFuture.completeExceptionally(new Exception("Looped through all"));
            return completableFuture;
        }
        if (firstPoint != null) {
            initialPoint = firstPoint;
        }
        String data = APIUtils.generateJsonRPCObject("KeyAssign", new KeyAssignParams(verifier, verifierId));
        Header[] headers = new Header[2];
        headers[0] = new Header("pubkeyx", torusNodePubs[nodeNum].getX());
        headers[1] = new Header("pubkeyy", torusNodePubs[nodeNum].getY());
        Integer finalInitialPoint = initialPoint;
        CompletableFuture<String> apir = APIUtils.post("https://signer.tor.us/api/sign", data, headers, true);
        apir.thenComposeAsync(signedData -> {
            Gson gson = new Gson();
            SignerResponse signerResponse = gson.fromJson(signedData, SignerResponse.class);
            Header[] signerHeaders = new Header[3];
            signerHeaders[0] = new Header("torus-timestamp", signerResponse.getTorus_timestamp());
            signerHeaders[1] = new Header("torus-nonce", signerResponse.getTorus_nonce());
            signerHeaders[2] = new Header("torus-signature", signerResponse.getTorus_signature());

            CompletableFuture<String> cf = APIUtils.post(endpoints[nodeNum], data, signerHeaders, false);
            cf.thenComposeAsync(resp -> {
                try {
                    Gson gsonTemp = new Gson();
                    JsonRPCResponse jsonRPCResponse = gson.fromJson(resp, JsonRPCResponse.class);
                    String result = jsonRPCResponse.getResult().toString();
                    if (result != null && !result.equals("")) {
                        completableFuture.complete(new KeyLookupResult(result, null));
                    } else {
                        Utils.keyAssign(endpoints, torusNodePubs, nodeNum + 1, finalInitialPoint, verifier, verifierId).thenComposeAsync(nextResp -> {
                            completableFuture.complete(nextResp);
                            return completableFuture;
                        }).exceptionally(ex -> {
                            completableFuture.completeExceptionally(ex);
                            return new KeyLookupResult(null, ex.toString());
                        });
                    }
                } catch (Exception e) {
                    Utils.keyAssign(endpoints, torusNodePubs, nodeNum + 1, finalInitialPoint, verifier, verifierId).thenComposeAsync(nextResp -> {
                        completableFuture.complete(nextResp);
                        return completableFuture;
                    }).exceptionally(ex -> {
                        completableFuture.completeExceptionally(ex);
                        return new KeyLookupResult(null, ex.toString());
                    });
                }
                return completableFuture;
            });
            return completableFuture;
        }).exceptionally(e -> {
            e.printStackTrace();
            completableFuture.completeExceptionally(e);
            return null;
        });


        return completableFuture;
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
}
