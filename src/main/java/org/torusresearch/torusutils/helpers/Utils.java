package org.torusresearch.torusutils.helpers;

import com.google.gson.Gson;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

public class Utils {
    private Utils() {
    }

    public static String thresholdSame(String[] arr, int threshold) {
        HashMap<String, Integer> hashMap = new HashMap();
        for (int i = 0; i < arr.length; i++) {
            Integer currentCount = hashMap.getOrDefault(arr[i], 0);
            int incrementedCount = currentCount + 1;
            if (incrementedCount == threshold) {
                return arr[i];
            }
            hashMap.put(arr[i], currentCount + 1);
        }
        return null;
    }

    public static String thresholdSame(List<String> list, int threshold) {
        String[] arr = new String[list.size()];
        list.toArray(arr);
        return Utils.thresholdSame(arr, threshold);
    }

    public static List<List<Integer>> kCombinations(int s, int k) {
        List<Integer> set = new ArrayList();
        for (int i = 0; i < s; i++) {
            set.add(new Integer(i));
        }
        return kCombinations(set, k);
    }

    public static List<List<Integer>> kCombinations(List<Integer> set, int k) {
        List<List<Integer>> combs = new ArrayList();
        if (k > set.size()) {
            return combs;
        }
        if (k == set.size()) {
            combs.add(set);
            return combs;
        }
        if (k == 1) {
            set.stream().forEach(i -> {
                ArrayList<Integer> arrList = new ArrayList();
                arrList.add(new Integer(i));
                combs.add(arrList);
            });
            return combs;
        }
        for (int i = 0; i < set.size() - k + 1; i++) {
            List<List<Integer>> tailCombs = Utils.kCombinations(set.subList(i + 1, set.size()), k - 1);
            for (int j = 0; j < tailCombs.size(); j++) {
                List<Integer> prependedComb = new ArrayList();
                prependedComb.add(set.get(i));
                for (int l = 0; l < tailCombs.get(j).size(); l++) {
                    prependedComb.add(tailCombs.get(j).get(l));
                }
                combs.add(prependedComb);
            }
        }
        return combs;
    }

    public static CompletableFuture<KeyLookupResult> keyLookup(String[] endpoints, String verifier, String verifierId) {
        int k = Math.floorDiv(endpoints.length, 2) + 1;
        List<CompletableFuture<String>> lookupPromises = new ArrayList<>();
        for (int i = 0; i < endpoints.length; i++) {
            lookupPromises.add(i, APIUtils.post(endpoints[i], APIUtils.generateJsonRPCObject("VerifierLookupRequest", new VerifierLookupRequestParams(verifier, verifierId))));
        }
        return new Some<>(lookupPromises, lookupResults -> {
            try {
                List<String> lookupShares = Arrays.asList(lookupResults)
                        .stream()
                        .filter(x -> x != "")
                        .collect(Collectors.toList());
                List<String> errorResults = lookupShares.stream().map(rpcResponse -> {
                    try {
                        Gson gson = new Gson();
                        return gson.fromJson(rpcResponse, JsonRPCResponse.class).getError().getData();
                    } catch (Exception e) {
                        return "";
                    }
                }).collect(Collectors.toList());
                String errorResult = thresholdSame(errorResults, k);
                List<String> keyResults = lookupShares.stream().map(rpcResponse -> {
                    try {
                        Gson gson = new Gson();
                        return gson.toJson(gson.fromJson(rpcResponse, JsonRPCResponse.class).getResult());
                    } catch (Exception e) {
                        return "";
                    }
                }).collect(Collectors.toList());
                String keyResult = thresholdSame(keyResults, k);
                if (errorResult != "" || keyResult != "") {
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
        headers[0] = new BasicHeader("pubkeyx", torusNodePubs[nodeNum].getX());
        headers[1] = new BasicHeader("pubkeyy", torusNodePubs[nodeNum].getY());
        Integer finalInitialPoint = initialPoint;
        CompletableFuture<String> apir = APIUtils.post("https://signer.tor.us/api/sign", data, headers);
        apir.thenComposeAsync(signedData -> {
            Gson gson = new Gson();
            SignerResponse signerResponse = gson.fromJson(signedData, SignerResponse.class);
            Header[] signerHeaders = new Header[3];
            signerHeaders[0] = new BasicHeader("torus-timestamp", signerResponse.getTorus_timestamp());
            signerHeaders[1] = new BasicHeader("torus-nonce", signerResponse.getTorus_nonce());
            signerHeaders[2] = new BasicHeader("torus-signature", signerResponse.getTorus_signature());

            CompletableFuture<String> cf = APIUtils.post(endpoints[nodeNum], data, signerHeaders);
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
}
