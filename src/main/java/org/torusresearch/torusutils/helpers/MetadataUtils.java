package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.helpers.encryption.Encryption.decrypt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.apis.APIUtils;
import org.torusresearch.torusutils.apis.requests.GetMetadataParams;
import org.torusresearch.torusutils.apis.requests.GetNonceParams;
import org.torusresearch.torusutils.apis.requests.GetNonceSetDataParams;
import org.torusresearch.torusutils.apis.requests.MetadataParams;
import org.torusresearch.torusutils.apis.requests.SetData;
import org.torusresearch.torusutils.apis.responses.GetMetadataResponse;
import org.torusresearch.torusutils.apis.responses.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.common.TorusKeyType;
import org.torusresearch.torusutils.types.common.ecies.Ecies;
import org.torusresearch.torusutils.types.common.ecies.EciesHexOmitCipherText;
import org.web3j.crypto.Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class MetadataUtils {
    private MetadataUtils() {
    }

    public static String decryptNodeData(@NotNull EciesHexOmitCipherText eciesData, @NotNull String ciphertextHex, @NotNull String privKey) throws Exception {
        Ecies eciesOpts = new Ecies(
                eciesData.iv,
                eciesData.ephemPublicKey,
                ciphertextHex,
                eciesData.mac
        );
        return Hex.toHexString(decrypt(privKey, eciesOpts));
    }


    public static MetadataParams generateMetadataParams(@NotNull Integer serverTimeOffset, @NotNull String message, @NotNull String privateKey, @NotNull String X, @NotNull String Y, @Nullable TorusKeyType keyType) {
        int timeStamp = serverTimeOffset + (int) (System.currentTimeMillis() / 1000L);
        SetData setData = new SetData(message, String.valueOf(timeStamp));

        Gson gson = new Gson();
        String setDataString = gson.toJson(setData);
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        BigInteger key = new BigInteger(privateKey, 16);
        byte[] hashedData = Hash.sha3(setDataString.getBytes(StandardCharsets.UTF_8));
        // Sign the hashed data using ECDSA with the private key
        SecureRandom random = new SecureRandom();
        ECDSASigner signer = new ECDSASigner();
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
        ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(key, domainParams);
        signer.init(true, new ParametersWithRandom(privKeyParams, random));
        BigInteger[] signature = signer.generateSignature(hashedData);

        String sig = Common.padLeft(signature[0].toString(16), '0', 64) + Common.padLeft(signature[1].toString(16), '0', 64) + Common.padLeft("", '0', 2);
        byte[] sigBytes = Base64.getEncoder().encode(Hex.decode(sig));
        String finalSig = new String(sigBytes, StandardCharsets.UTF_8);
        return new MetadataParams(X, Y, setData, finalSig, null, keyType);
    }

    public static GetMetadataResponse getMetadata(String legacyMetadataHost, GetMetadataParams data) throws ExecutionException, InterruptedException {
        Gson gson = new Gson();
        String metadata = gson.toJson(data, GetMetadataParams.class);
        String metadataApiResponse = APIUtils.post(legacyMetadataHost + "/get", metadata, true).get();
        return gson.fromJson(metadataApiResponse, GetMetadataResponse.class);
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
        if (jsonObject.has("ipfs")) {
            jsonObject.remove("ipfs");
        }
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
}
