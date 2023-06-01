package org.torusresearch.torusutils.helpers;

import com.google.gson.Gson;

import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.GetPubKeyOrKeyAssignRequestParams;
import org.torusresearch.torusutils.apis.JsonRPCResponse;
import org.torusresearch.torusutils.apis.KeyAssignParams;
import org.torusresearch.torusutils.apis.KeyLookupResult;
import org.torusresearch.torusutils.apis.SignerResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import okhttp3.internal.http2.Header;

public class Utils {
    private Utils() {
    }

    public static String thresholdSame(String[] arr, int threshold) {
        HashMap<String, Integer> hashMap = new HashMap<>();
        for (String s : arr) {
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
        if (k > set.size()) {
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

    public static CompletableFuture<KeyLookupResult> waitKeyLookup(String[] endpoints, String verifier, String verifierId, int timeout) {
        CompletableFuture<KeyLookupResult> completableFuture = new CompletableFuture<>();
        try {
            Thread.sleep(timeout);
        } catch (InterruptedException e) {
            completableFuture.completeExceptionally(e);
        }
        Utils.keyLookup(endpoints, verifier, verifierId, "").whenComplete((res, err) -> {
            if (err != null) {
                completableFuture.completeExceptionally(err);
            }
            completableFuture.complete(res);
        });
        return completableFuture;
    }

    public static CompletableFuture<KeyLookupResult> keyLookup(String[] endpoints, String verifier, String verifierId, String extendedVerifierId) {
        int k = endpoints.length / 2 + 1;
        List<CompletableFuture<String>> lookupPromises = new ArrayList<>();
        for (int i = 0; i < endpoints.length; i++) {
            lookupPromises.add(i, APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("GetPubKeyOrKeyAssign",
                    new GetPubKeyOrKeyAssignRequestParams(verifier, verifierId, extendedVerifierId,
                            true, true)), false));
        }
        return new Some<>(lookupPromises, (lookupResults, resolved) -> {
            try {
                List<String> errorResults = new ArrayList<>();
                List<String> keyResults = new ArrayList<>();
                Gson gson = new Gson();
                for (String x : lookupResults) {
                    if (x != null && !x.equals("")) {
                        try {
                            JsonRPCResponse response = gson.fromJson(x, JsonRPCResponse.class);
                            keyResults.add(Utils.convertToJsonObject(response.getResult()));
                        } catch (Exception e) {
                            keyResults.add("");
                        }
                    }
                }
                for (String x : lookupResults) {
                    if (x != null && !x.equals("")) {
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
                if ((errorResult != null && !errorResult.equals("")) || (keyResult != null && !keyResult.equals(""))) {
                    return CompletableFuture.completedFuture(new KeyLookupResult(keyResult, errorResult, nodeIndexes, nonceResult));
                }
                CompletableFuture<KeyLookupResult> failedFuture = new CompletableFuture<>();
                failedFuture.completeExceptionally(new Exception("invalid results from KeyLookup " + gson.toJson(lookupResults)));
                return failedFuture;
            } catch (Exception e) {
                return null;
            }
        }).getCompletableFuture();
    }

    public static CompletableFuture<KeyLookupResult> keyAssign(String[] endpoints, TorusNodePub[] torusNodePubs, Integer lastPoint, Integer firstPoint, String verifier, String verifierId, String signerHost, String network) {
        Integer nodeNum, initialPoint = null;
        CompletableFuture<KeyLookupResult> completableFuture = new CompletableFuture<>();

        if (lastPoint == null) {
            nodeNum = new Random().nextInt(endpoints.length);
            initialPoint = nodeNum;
        } else {
            nodeNum = lastPoint % endpoints.length;
        }
        if (nodeNum.equals(firstPoint)) {
            completableFuture.completeExceptionally(new Exception("Looped through all. No node available for key assignment"));
            return completableFuture;
        }
        if (firstPoint != null) {
            initialPoint = firstPoint;
        }
        String data = APIUtils.generateJsonRPCObject("KeyAssign", new KeyAssignParams(verifier, verifierId));
        Header[] headers = new Header[3];
        headers[0] = new Header("pubkeyx", torusNodePubs[nodeNum].getX());
        headers[1] = new Header("pubkeyy", torusNodePubs[nodeNum].getY());
        headers[2] = new Header("network", network);
        Integer finalInitialPoint = initialPoint;
        CompletableFuture<String> apir = APIUtils.post(signerHost, data, headers, true);
        apir.whenCompleteAsync((signedData, err) -> {
            if (err != null) {
                // if signer fails, we just return
                completableFuture.completeExceptionally(err);
                return;
            }
            try {
                Gson gson = new Gson();
                SignerResponse signerResponse = gson.fromJson(signedData, SignerResponse.class);
                Header[] signerHeaders = new Header[3];
                if (signerResponse.getTorus_timestamp() == null || signerResponse.getTorus_nonce() == null || signerResponse.getTorus_signature() == null) {
                    completableFuture.completeExceptionally(new Exception("Invalid signer response. Please retry!"));
                    return;
                }
                signerHeaders[0] = new Header("torus-timestamp", signerResponse.getTorus_timestamp());
                signerHeaders[1] = new Header("torus-nonce", signerResponse.getTorus_nonce());
                signerHeaders[2] = new Header("torus-signature", signerResponse.getTorus_signature());

                CompletableFuture<String> cf = APIUtils.post(endpoints[nodeNum], data, signerHeaders, false);
                cf.whenCompleteAsync((resp, keyAssignErr) -> {
                    try {
                        // we only retry if keyassign api fails..
                        // All other cases, we just complete exceptionally
                        if (keyAssignErr != null) {
                            Utils.keyAssign(endpoints, torusNodePubs, nodeNum + 1, finalInitialPoint, verifier, verifierId, signerHost, network).whenCompleteAsync((res2, err2) -> {
                                if (err2 != null) {
                                    completableFuture.completeExceptionally(err2);
                                    return;
                                }
                                completableFuture.complete(res2);
                            });
                            return;
                        }
                        JsonRPCResponse jsonRPCResponse = gson.fromJson(resp, JsonRPCResponse.class);
                        String result = jsonRPCResponse.getResult().toString();
                        if (result != null && !result.equals("")) {
                            completableFuture.complete(new KeyLookupResult(result, null, nodeIndexes, nonceResult));
                        } else {
                            Utils.keyAssign(endpoints, torusNodePubs, nodeNum + 1, finalInitialPoint, verifier, verifierId, signerHost, network).whenCompleteAsync((res2, err2) -> {
                                if (err2 != null) {
                                    completableFuture.completeExceptionally(err2);
                                    return;
                                }
                                completableFuture.complete(res2);
                            });
                        }
                    } catch (Exception ex) {
                        completableFuture.completeExceptionally(ex);
                    }
                });
            } catch (Exception e) {
                completableFuture.completeExceptionally(e);
            }
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

    public static String stripPaddingLeft(String inputString, Character padChar) {
        StringBuilder sb = new StringBuilder(inputString);
        while (sb.length() > 1 && sb.charAt(0) == padChar) {
            sb.deleteCharAt(0);
        }
        return sb.toString();
    }

    public static String convertToJsonObject(Object obj) {
        Gson gson = new Gson();
        return obj == null ? "" : gson.toJson(obj);
    }
}
