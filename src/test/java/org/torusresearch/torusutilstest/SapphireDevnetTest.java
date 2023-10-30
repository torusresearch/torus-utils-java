package org.torusresearch.torusutilstest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auth0.jwt.algorithms.Algorithm;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.NodeDetails;
import org.torusresearch.fetchnodedetails.types.TorusNetwork;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.ImportedShare;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.RetrieveSharesResponse;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.TorusCtorOptions;
import org.torusresearch.torusutils.types.TorusException;
import org.torusresearch.torusutils.types.TorusPublicKey;
import org.torusresearch.torusutils.types.TypeOfUser;
import org.torusresearch.torusutils.types.VerifierArgs;
import org.torusresearch.torusutilstest.utils.JwtUtils;
import org.torusresearch.torusutilstest.utils.PemUtils;
import org.torusresearch.torusutilstest.utils.VerifyParams;
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
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

public class SapphireDevnetTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_IMPORT_EMAIL = "importeduser5@tor.us";
    static String TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";
    static String HashEnabledVerifier = "torus-test-verifierid-hash";

    static String TORUS_TEST_EMAIL = "saasas@tr.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.SAPPHIRE_DEVNET);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.SAPPHIRE_DEVNET.toString());
        opts.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
        opts.setEnableOneKey(true);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("should fetch public address of a legacy v1 user")
    @Test
    public void testFetchPublicAddressOfLegacyV1User() throws ExecutionException, InterruptedException {
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.TESTNET);
        VerifierArgs verifierDetails = new VerifierArgs("google-lrc", "himanshu@tor.us", ""); // Replace with the actual verifier ID
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.TESTNET.toString());
        opts.setAllowHost("https://signer.tor.us/api/allow");
        opts.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
        opts.setEnableOneKey(true);
        torusUtils = new TorusUtils(opts);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google-lrc", "himanshu@tor.us").get();
        TorusPublicKey publicKeyData = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), verifierDetails).get();
        assertEquals(TypeOfUser.v1, publicKeyData.getMetadata().getTypeOfUser());
        assertThat(publicKeyData).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xf1e76fcDD28b5AA06De01de508fF21589aB9017E",
                        "b3f2b4d8b746353fe670e0c39ac9adb58056d4d7b718d06b623612d4ec49268b",
                        "ac9f79dff78add39cdba380dbbf517c20cf2c1e06b32842a90a84a31f6eb9a9a"),
                new FinalPubKeyData("0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1",
                        "12f6b90d66bda29807cf9ff14b2e537c25080154fc4fafed446306e8356ff425",
                        "e7c92e164b83e1b53e41e5d87d478bb07d7b19d105143e426e1ef08f7b37f224"),
                new Metadata(null, new BigInteger("186a20d9b00315855ff5622a083aca6b2d34ef66ef6e0a4de670f5b2fde37e0d", 16),
                        TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("should be able to login a v1 user")
    @Test
    public void shouldLoginForV1User() throws ExecutionException, InterruptedException, TorusException {
        String verifier = "google-lrc";
        String email = "himanshu@tor.us";
        String token = JwtUtils.generateIdToken(email, algorithmRs);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.TESTNET.toString());
        opts.setAllowHost("https://signer.tor.us/api/allow");
        opts.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
        torusUtils = new TorusUtils(opts);
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.TESTNET);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(verifier, email).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", email);
        }}, token).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xbeFfcC367D741C53A63F50eA805c1e93d3C64fEc",
                        "2b1c47c8fbca61ee7f82a8aff53a357f6b66af0dffbef6a3e3ac649180616e51",
                        "fef450a5263f7c57605dd439225faee830943cb484e8dfe1f3c82c3d538f61af",
                        "dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9"),
                new OAuthKeyData("0xbeFfcC367D741C53A63F50eA805c1e93d3C64fEc",
                        "2b1c47c8fbca61ee7f82a8aff53a357f6b66af0dffbef6a3e3ac649180616e51",
                        "fef450a5263f7c57605dd439225faee830943cb484e8dfe1f3c82c3d538f61af",
                        "dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9"),
                new SessionData(new ArrayList<>(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        String verifier = TORUS_TEST_VERIFIER;
        VerifierArgs args = new VerifierArgs(verifier, TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x4924F91F5d6701dDd41042D94832bB17B76F316F", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xac997dE675Fb69FCb0F4115A23c0061A892A2772",
                        "9508a251dfc4146a132feb96111c136538f4fabd20fc488dbcaaf762261c1528",
                        "f9128bc7403bab6d45415cad01dd0ba0924628cfb6bf51c17e77aa8ca43b3cfe"),
                new FinalPubKeyData("0x4924F91F5d6701dDd41042D94832bB17B76F316F",
                        "f3eaf63bf1fd645d4159832ccaad7f42457e287ac929363ba636eb7e87978bff",
                        "f3b9d8dd91927a89ec45199ad697fe3fa01b8b836710143a0babb1a4eb35f1cd"),
                new Metadata(new GetOrSetNonceResult.PubNonce("78a88b99d960808543e75076529c913c1678bc7fafbb943f1ce58235fd2f4e0c",
                        "6b451282135dfacd22561e0fb5bf21aea7b1f26f2442164b82b0e4c8f152f7a7"),
                        new BigInteger("376df8a62e2e72a2b3e87e97c85f86b3f2dac41082ddeb863838d80462deab5e", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("should keep public address same")
    @Test
    public void shouldKeyPublicAddressSame() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        VerifierArgs args = new VerifierArgs(TORUS_TEST_VERIFIER, email, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey result1 = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        TorusPublicKey result2 = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertThat(result1.getFinalKeyData()).isEqualToComparingFieldByFieldRecursively(result2.getFinalKeyData());
        assertThat(result1.getoAuthKeyData()).isEqualToComparingFieldByFieldRecursively(result2.getoAuthKeyData());
        assertThat(result1.getMetadata()).isEqualToComparingFieldByFieldRecursively(result2.getMetadata());
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        VerifierArgs args = new VerifierArgs(TORUS_TEST_VERIFIER, email, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getEvmAddress(), "");
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException {
        String token = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, token).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("04eb166ddcf59275a210c7289dca4a026f87a33fd2d6ed22f56efae7eab4052c"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x4924F91F5d6701dDd41042D94832bB17B76F316F",
                        "f3eaf63bf1fd645d4159832ccaad7f42457e287ac929363ba636eb7e87978bff",
                        "f3b9d8dd91927a89ec45199ad697fe3fa01b8b836710143a0babb1a4eb35f1cd",
                        "04eb166ddcf59275a210c7289dca4a026f87a33fd2d6ed22f56efae7eab4052c"),
                new OAuthKeyData("0xac997dE675Fb69FCb0F4115A23c0061A892A2772",
                        "9508a251dfc4146a132feb96111c136538f4fabd20fc488dbcaaf762261c1528",
                        "f9128bc7403bab6d45415cad01dd0ba0924628cfb6bf51c17e77aa8ca43b3cfe",
                        "cd7d1dc7aec71fd2ee284890d56ac34d375bbc15ff41a1d87d088170580b9b0f"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce("78a88b99d960808543e75076529c913c1678bc7fafbb943f1ce58235fd2f4e0c",
                        "6b451282135dfacd22561e0fb5bf21aea7b1f26f2442164b82b0e4c8f152f7a7"),
                        new BigInteger("376df8a62e2e72a2b3e87e97c85f86b3f2dac41082ddeb863838d80462deab5e", 16), TypeOfUser.v2,
                        false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("New User Login test")
    @Test
    public void shouldNewUserLogin() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        String token = JwtUtils.generateIdToken(email, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", email);
        }}, token).get();
        assert (retrieveSharesResponse.getMetadata().getTypeOfUser().equals(TypeOfUser.v2));
        assertEquals(retrieveSharesResponse.getMetadata().isUpgraded(), true);
        assertEquals("", retrieveSharesResponse.finalKeyData.getEvmAddress());
        assertEquals(null, retrieveSharesResponse.finalKeyData.getX());
        assertEquals(null, retrieveSharesResponse.finalKeyData.getY());
        assertEquals("", retrieveSharesResponse.finalKeyData.getPrivKey());
        assertNotEquals("", retrieveSharesResponse.oAuthKeyData.getEvmAddress());
        assertNotEquals("", retrieveSharesResponse.oAuthKeyData.getX());
        assertNotEquals("", retrieveSharesResponse.oAuthKeyData.getY());
        assertNotEquals("", retrieveSharesResponse.oAuthKeyData.getPrivKey());
        assertNotEquals(0, retrieveSharesResponse.sessionData.getSessionTokenData().size());
        assertNotEquals("", retrieveSharesResponse.sessionData.getSessionAuthKey());
        assertEquals("", retrieveSharesResponse.metadata.getPubNonce().getX());
        assertEquals("", retrieveSharesResponse.metadata.getPubNonce().getY());
        assertNotEquals(0, retrieveSharesResponse.nodesData.getNodeIndexes().size());
    }

    @DisplayName("Should be able to login even when node is down")
    @Test
    public void shouldLoginWhenNodeIsDown() throws Exception {
        String token = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        torusNodeEndpoints[1] = "https://example.com";
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(torusNodeEndpoints, nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, token, new ImportedShare[]{}).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("04eb166ddcf59275a210c7289dca4a026f87a33fd2d6ed22f56efae7eab4052c"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x4924F91F5d6701dDd41042D94832bB17B76F316F",
                        "f3eaf63bf1fd645d4159832ccaad7f42457e287ac929363ba636eb7e87978bff",
                        "f3b9d8dd91927a89ec45199ad697fe3fa01b8b836710143a0babb1a4eb35f1cd",
                        "04eb166ddcf59275a210c7289dca4a026f87a33fd2d6ed22f56efae7eab4052c"),
                new OAuthKeyData("0xac997dE675Fb69FCb0F4115A23c0061A892A2772",
                        "9508a251dfc4146a132feb96111c136538f4fabd20fc488dbcaaf762261c1528",
                        "f9128bc7403bab6d45415cad01dd0ba0924628cfb6bf51c17e77aa8ca43b3cfe",
                        "cd7d1dc7aec71fd2ee284890d56ac34d375bbc15ff41a1d87d088170580b9b0f"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce("78a88b99d960808543e75076529c913c1678bc7fafbb943f1ce58235fd2f4e0c",
                        "6b451282135dfacd22561e0fb5bf21aea7b1f26f2442164b82b0e4c8f152f7a7"),
                        new BigInteger("376df8a62e2e72a2b3e87e97c85f86b3f2dac41082ddeb863838d80462deab5e", 16), TypeOfUser.v2,
                        false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("should fetch public address when verifierID hash enabled")
    @Test
    public void shouldFetchPubAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
                        "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
                        "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0"),
                new FinalPubKeyData("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
                        "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
                        "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e"),
                new Metadata(new GetOrSetNonceResult.PubNonce("d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
                        "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e"),
                        new BigInteger("51eb06f7901d5a8562274d3e53437328ca41ad96926f075122f6bd50e31be52d", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Should fetch user type and public address when verifierID hash enabled")
    @Test
    public void testFetchUserTypeAndPublicAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
                        "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
                        "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0"),
                new FinalPubKeyData("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
                        "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
                        "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e"),
                new Metadata(new GetOrSetNonceResult.PubNonce("d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
                        "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e"),
                        new BigInteger("51eb06f7901d5a8562274d3e53437328ca41ad96926f075122f6bd50e31be52d", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException, TorusException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse result = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_AGGREGATE_VERIFIER, new HashMap<String, Object>() {{
            put("verify_params", new VerifyParams[]{new VerifyParams(idToken, TORUS_TEST_EMAIL)});
            put("sub_verifier_ids", new String[]{TORUS_TEST_VERIFIER});
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, hashedIdToken).get();
        assertNotNull(result.getFinalKeyData().getEvmAddress());
        assertNotNull(result.oAuthKeyData.evmAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertNotNull(result.metadata.nonce);
    }

    @DisplayName("should allow test tss verifier id to fetch shares")
    @Test
    public void shouldAllowTestTssVerifierIdToFetchShares() throws ExecutionException, InterruptedException, TorusException {
        String email = JwtUtils.getRandomEmail();
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        String idToken = JwtUtils.generateIdToken(email, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        RetrieveSharesResponse result = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("extended_verifier_id", tssVerifierId);
            put("verifier_id", email);
        }}, idToken).get();
        assertNotNull(result.finalKeyData.privKey);
        assertNotNull(result.oAuthKeyData.evmAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertEquals(new BigInteger("0"), result.metadata.nonce);
        assertTrue(result.metadata.upgraded);
    }

    @DisplayName("should be able to login when verifierID hash enabled")
    @Test
    public void testShouldBeAbleToLoginWhenVerifierIdHashEnabled() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(torusNodeEndpoints, nodeDetails.getTorusIndexes(), HashEnabledVerifier, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, idToken).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("066270dfa345d3d0415c8223e045f366b238b50870de7e9658e3c6608a7e2d32"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
                        "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
                        "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e",
                        "066270dfa345d3d0415c8223e045f366b238b50870de7e9658e3c6608a7e2d32"),
                new OAuthKeyData("0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
                        "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
                        "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0",
                        "b47769e81328794adf3534e58d02803ca2a5e4588db81780f5bf679c77988946"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce("d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
                        "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e"),
                        new BigInteger("51eb06f7901d5a8562274d3e53437328ca41ad96926f075122f6bd50e31be52d", 16), TypeOfUser.v2,
                        false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
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
        TorusPublicKey result = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), verifierArgs).get();
        assertNotNull(result.finalKeyData.evmAddress);
        assertNotNull(result.oAuthKeyData.evmAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertFalse(result.metadata.upgraded);
    }

}
