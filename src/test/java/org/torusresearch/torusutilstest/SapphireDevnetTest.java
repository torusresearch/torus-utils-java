package org.torusresearch.torusutilstest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.Gson;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.NodeDetails;
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.TorusUtilsExtraParams;
import org.torusresearch.torusutils.types.VerifierArgs;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.VerifyParam;
import org.torusresearch.torusutils.types.common.PubNonce;
import org.torusresearch.torusutils.types.common.SessionToken;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TorusOptions;
import org.torusresearch.torusutils.types.common.TorusPublicKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;
import org.torusresearch.torusutilstest.utils.JwtUtils;
import org.torusresearch.torusutilstest.utils.PemUtils;
import org.web3j.crypto.Hash;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class SapphireDevnetTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_IMPORT_EMAIL = "devnettestuser@tor.us";
    static String TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";
    static String HashEnabledVerifier = "torus-test-verifierid-hash";
    static String TORUS_TEST_EMAIL = "devnettestuser@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, TorusUtilError {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(Web3AuthNetwork.SAPPHIRE_DEVNET);
        TorusOptions opts = new TorusOptions("YOUR_CLIENT_ID", Web3AuthNetwork.SAPPHIRE_DEVNET, null, 0, true);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("should fetch public address of a legacy v1 user")
    @Test
    public void testFetchPublicAddressOfLegacyV1User() throws Exception {
        fetchNodeDetails = new FetchNodeDetails(Web3AuthNetwork.TESTNET);
        VerifierArgs verifierDetails = new VerifierArgs("google-lrc", "himanshu@tor.us", ""); // Replace with the actual verifier ID
        TorusOptions opts = new TorusOptions( "BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4", Web3AuthNetwork.TESTNET, null, 0 , true);
        torusUtils = new TorusUtils(opts);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google-lrc", "himanshu@tor.us").get();
        TorusPublicKey publicKeyData = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), verifierDetails);
        assertEquals(TypeOfUser.v1, publicKeyData.getMetadata().getTypeOfUser());
        assertThat(publicKeyData).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xf1e76fcDD28b5AA06De01de508fF21589aB9017E",
                        "b3f2b4d8b746353fe670e0c39ac9adb58056d4d7b718d06b623612d4ec49268b",
                        "ac9f79dff78add39cdba380dbbf517c20cf2c1e06b32842a90a84a31f6eb9a9a"),
                new FinalPubKeyData("0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1",
                        "12f6b90d66bda29807cf9ff14b2e537c25080154fc4fafed446306e8356ff425",
                        "e7c92e164b83e1b53e41e5d87d478bb07d7b19d105143e426e1ef08f7b37f224"),
                new Metadata(null, new BigInteger("186a20d9b00315855ff5622a083aca6b2d34ef66ef6e0a4de670f5b2fde37e0d", 16),
                        TypeOfUser.v1, false, publicKeyData.getMetadata().serverTimeOffset),
                new NodesData(publicKeyData.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws Exception {
        String verifier = TORUS_TEST_VERIFIER;
        VerifierArgs args = new VerifierArgs(verifier, TORUS_TEST_EMAIL, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), args);
        assertTrue(torusPublicKey.getMetadata().getServerTimeOffset().intValue() < 20);
        assertEquals("0x137B3607958562D03Eb3C6086392D1eFa01aA6aa", torusPublicKey.oAuthKeyData.walletAddress);
        assertEquals("0x462A8BF111A55C9354425F875F89B22678c0Bc44", torusPublicKey.finalKeyData.walletAddress);
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x137B3607958562D03Eb3C6086392D1eFa01aA6aa",
                        "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
                        "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5"),
                new FinalPubKeyData("0x462A8BF111A55C9354425F875F89B22678c0Bc44",
                        "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1",
                        "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507"),
                new Metadata(new PubNonce("5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc",
                        "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed"),
                        BigInteger.ZERO, TypeOfUser.v2, false, torusPublicKey.getMetadata().serverTimeOffset),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should keep public address same")
    @Test
    public void shouldKeyPublicAddressSame() throws Exception {
        String email = JwtUtils.getRandomEmail();
        VerifierArgs args = new VerifierArgs(TORUS_TEST_VERIFIER, email, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey result1 = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), args);
        TorusPublicKey result2 = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), args);
        assertThat(result1.getFinalKeyData()).isEqualToComparingFieldByFieldRecursively(result2.getFinalKeyData());
        assertThat(result1.getoAuthKeyData()).isEqualToComparingFieldByFieldRecursively(result2.getoAuthKeyData());
    }

    @DisplayName("should be able to key assign")
    @Test
    public void shouldKeyAssign() throws Exception {
        String email = JwtUtils.getRandomEmail();
        VerifierArgs args = new VerifierArgs(TORUS_TEST_VERIFIER, email, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), args);
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getWalletAddress());
        assertNotNull(publicAddress.getFinalKeyData().getWalletAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getWalletAddress(), "");
    }

    @DisplayName("should be able to login")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException {
        String token = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, null, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        TorusKey torusKey = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), TORUS_TEST_VERIFIER,
                verifierParams, token, null).get();
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x462A8BF111A55C9354425F875F89B22678c0Bc44",
                        "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1",
                        "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507",
                        "230dad9f42039569e891e6b066ff5258b14e9764ef5176d74aeb594d1a744203"),
                new OAuthKeyData("0x137B3607958562D03Eb3C6086392D1eFa01aA6aa",
                        "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b",
                        "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5",
                        "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa"),
                new SessionData(torusKey.sessionData.getSessionTokenData(), torusKey.sessionData.getSessionAuthKey()),
                new Metadata(new PubNonce("5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc",
                        "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed"),
                        new BigInteger("b7d126751b68ecd09e371a23898e6819dee54708a5ead4f6fe83cdc79c0f1c4a", 16), TypeOfUser.v2,
                        false, torusKey.metadata.serverTimeOffset),
                new NodesData(torusKey.nodesData.nodeIndexes)
        ));
    }


    @DisplayName("should fetch pubic address of tssVerifierId")
    @Test
    public void shouldFetchPubicAddressOfTssVerifierId() throws Exception {
        String email = TORUS_EXTENDED_VERIFIER_EMAIL;
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        VerifierArgs verifierArgs = new VerifierArgs(TORUS_TEST_VERIFIER, email, tssVerifierId);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), verifierArgs);
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30",
                        "d45d4ad45ec643f9eccd9090c0a2c753b1c991e361388e769c0dfa90c210348c",
                        "fdc151b136aa7df94e97cc7d7007e2b45873c4b0656147ec70aad46e178bce1e"),
                new FinalPubKeyData("0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30",
                        "d45d4ad45ec643f9eccd9090c0a2c753b1c991e361388e769c0dfa90c210348c",
                        "fdc151b136aa7df94e97cc7d7007e2b45873c4b0656147ec70aad46e178bce1e"),
                new Metadata(torusPublicKey.getMetadata().pubNonce,
                        new BigInteger("0"), TypeOfUser.v2, false, torusPublicKey.getMetadata().serverTimeOffset),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should fetch public address when verifierID hash enabled")
    @Test
    public void shouldFetchPubAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, null);
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, args);
        assertEquals("0x8a7e297e20804786767B1918a5CFa11683e5a3BB", torusPublicKey.getFinalKeyData().getWalletAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xaEafa3Fc7349E897F8fCe981f55bbD249f12aC8C",
                        "72d9172d7edc623266d6c625db91505e6b64a5524e6d7c7c0184b1bbdea1e986",
                        "8c26d557a0a9cb22dc2a30d36bf67de93a0eb6d4ef503a849c7de2d14dcbdaaa"),
                new FinalPubKeyData("0x8a7e297e20804786767B1918a5CFa11683e5a3BB",
                        "7927d5281aea24fd93f41696f79c91370ec0097ff65e83e95691fffbde6d733a",
                        "f22735f0e72ff225274cf499d50b240b7571063e0584471b2b4dab337ad5d8da"),
                new Metadata(new PubNonce("5712d789f7ecf3435dd9bf1136c2daaa634f0222d64e289d2abe30a729a6a22b",
                        "2d2b4586fd5fd9d15c22f66b61bc475742754a8b96d1edb7b2590e4c4f97b3f0"),
                        new BigInteger("0"), TypeOfUser.v2, false, torusPublicKey.getMetadata().serverTimeOffset),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Should fetch user type and public address when verifierID hash enabled")
    @Test
    public void testFetchUserTypeAndPublicAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, null);
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, args);
        assertTrue(torusPublicKey.getMetadata().getServerTimeOffset() < 20);
        assertEquals("0x8a7e297e20804786767B1918a5CFa11683e5a3BB", torusPublicKey.getFinalKeyData().getWalletAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xaEafa3Fc7349E897F8fCe981f55bbD249f12aC8C",
                        "72d9172d7edc623266d6c625db91505e6b64a5524e6d7c7c0184b1bbdea1e986",
                        "8c26d557a0a9cb22dc2a30d36bf67de93a0eb6d4ef503a849c7de2d14dcbdaaa"),
                new FinalPubKeyData("0x8a7e297e20804786767B1918a5CFa11683e5a3BB",
                        "7927d5281aea24fd93f41696f79c91370ec0097ff65e83e95691fffbde6d733a",
                        "f22735f0e72ff225274cf499d50b240b7571063e0584471b2b4dab337ad5d8da"),
                new Metadata(new PubNonce("5712d789f7ecf3435dd9bf1136c2daaa634f0222d64e289d2abe30a729a6a22b",
                        "2d2b4586fd5fd9d15c22f66b61bc475742754a8b96d1edb7b2590e4c4f97b3f0"),
                        new BigInteger("0"), TypeOfUser.v2, false, torusPublicKey.getMetadata().serverTimeOffset),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should be able to aggregate login")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, new String[]{TORUS_TEST_VERIFIER}, new VerifyParam[]{new VerifyParam(idToken, TORUS_TEST_EMAIL)});
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        TorusKey result = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), TORUS_TEST_AGGREGATE_VERIFIER,
                verifierParams, hashedIdToken, null).get();
        assertNotNull(result.getFinalKeyData().getWalletAddress());
        assertNotNull(result.oAuthKeyData.walletAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertNotNull(result.metadata.nonce);
    }

    @DisplayName("should be able to login when verifierID hash enabled")
    @Test
    public void testShouldBeAbleToLoginWhenVerifierIdHashEnabled() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, null, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        TorusKey torusKey = torusUtils.retrieveShares(torusNodeEndpoints, HashEnabledVerifier,
                verifierParams, idToken, null).get();
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x8a7e297e20804786767B1918a5CFa11683e5a3BB",
                        "7927d5281aea24fd93f41696f79c91370ec0097ff65e83e95691fffbde6d733a",
                        "f22735f0e72ff225274cf499d50b240b7571063e0584471b2b4dab337ad5d8da",
                        "f161f63a84f1c935525ec0bda74bc5a15de6a9a7be28fad237ef6162df335fe6"),
                new OAuthKeyData("0xaEafa3Fc7349E897F8fCe981f55bbD249f12aC8C",
                        "72d9172d7edc623266d6c625db91505e6b64a5524e6d7c7c0184b1bbdea1e986",
                        "8c26d557a0a9cb22dc2a30d36bf67de93a0eb6d4ef503a849c7de2d14dcbdaaa",
                        "62e110d9d698979c1966d14b2759006cf13be7dfc86a63ff30812e2032163f2f"),
                new SessionData(torusKey.sessionData.getSessionTokenData(), torusKey.sessionData.getSessionAuthKey()),
                new Metadata(new PubNonce("5712d789f7ecf3435dd9bf1136c2daaa634f0222d64e289d2abe30a729a6a22b",
                        "2d2b4586fd5fd9d15c22f66b61bc475742754a8b96d1edb7b2590e4c4f97b3f0"),
                        new BigInteger("8e80e560ae59319938f7ef727ff2c5346caac1c7f5be96d3076e3342ad1d20b7", 16), TypeOfUser.v2,
                        false, torusKey.metadata.serverTimeOffset),
                new NodesData(torusKey.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("should assign key to tss verifier id")
    @Test
    public void shouldAssignKeyToTssVerifierId() throws Exception {
        String email = JwtUtils.getRandomEmail();
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        VerifierArgs verifierArgs = new VerifierArgs(TORUS_TEST_VERIFIER, email, tssVerifierId);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        TorusPublicKey result = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), verifierArgs);
        assertNotNull(result.finalKeyData.walletAddress);
        assertNotNull(result.oAuthKeyData.walletAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertFalse(result.metadata.upgraded);
    }

    @DisplayName("should be able to update the `sessionTime` of the token signature data")
    @Test
    public void shouldUpdateSessionTimeOfTokenSignatureData() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, null, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeEndpoints();

        int customSessionTime = 3600;
        torusUtils.setSessionTime(customSessionTime);

        TorusKey torusKey = torusUtils.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER,
                verifierParams, idToken, null).get();

        List<Map<String, String>> signatures = new ArrayList<>();
        for (SessionToken sessionToken : torusKey.getSessionData().getSessionTokenData()) {
            Map<String, String> signature = new HashMap<>();
            signature.put("data", sessionToken.getToken());
            signature.put("sig", sessionToken.getSignature());
            signatures.add(signature);
        }

        List<Map<String, Object>> parsedSigsData = new ArrayList<>();
        for (Map<String, String> sig : signatures) {
            byte[] decodedBytes = Base64.getDecoder().decode(sig.get("data"));
            String decodedString = new String(decodedBytes);
            HashMap parsedSigData = new Gson().fromJson(decodedString, HashMap.class);
            //parsedSigsData.add(parsedSigData);
        }

        long currentTimeSec = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
        for (Map<String, Object> ps : parsedSigsData) {
            long sessionTime = ((Number) ps.get("exp")).longValue() - currentTimeSec;
            assert sessionTime > (customSessionTime - 30);
            assert customSessionTime <= sessionTime;
        }
    }

    @Test
    public void testShouldBeAbleToImportKeyForANewUser() throws Exception {
        String fakeEmail = JwtUtils.getRandomEmail();
        String jwt = JwtUtils.generateIdToken(fakeEmail, algorithmRs);
        String privateKey = Hex.toHexString(KeyUtils.serializePrivateKey(KeyUtils.generateKeyPair().getPrivate()));
        VerifierParams verifierParams = new VerifierParams(fakeEmail, null, null, null);

        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, fakeEmail).get();
        TorusKey val = torusUtils.importPrivateKey(
                nodeDetails.getTorusNodeSSSEndpoints(),
                nodeDetails.getTorusIndexes(),
                nodeDetails.getTorusNodePub(),
                TORUS_TEST_VERIFIER,
                verifierParams,
                jwt,
                privateKey,
                new TorusUtilsExtraParams()
        ).get();

        assertEquals(val.getFinalKeyData().getPrivKey(), privateKey);

        jwt = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        TorusKey shareRetrieval = torusUtils.retrieveShares(
                nodeDetails.getTorusNodeSSSEndpoints(),
                TORUS_TEST_VERIFIER,
                verifierParams,
                jwt, null
        ).get();
        assertEquals(shareRetrieval.getFinalKeyData().getPrivKey(), privateKey);
        TorusPublicKey addressRetrieval = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(),
                new VerifierArgs(TORUS_TEST_VERIFIER, fakeEmail));
        String publicAddress = KeyUtils.generateAddressFromPrivKey(privateKey);
        String retrievedAddress = KeyUtils.getPublicKeyFromCoords(
                addressRetrieval.getFinalKeyData().getX(),
                addressRetrieval.getFinalKeyData().getY(), true
        );
        assertEquals(publicAddress, retrievedAddress);

    }
}
