package org.torusresearch.torusutilstest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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

public class CyanTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws ExecutionException, InterruptedException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.CYAN);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.CYAN.toString());
        opts.setAllowHost("https://signer-polygon.tor.us/api/allow");
        opts.setSignerHost("https://signer-polygon.tor.us/api/sign");
        opts.setClientId("BA5akJpGy6j5bVNL33RKpe64AXTiPGTSCYOI0i-BbDtbOYWtFQNdLzaC-WKibRtQ0sV_TVHC42TdOTbyZXdN-XI");
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("tkey-google-cyan", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x3507F0d192a44E436B8a6C32a37d57D022861b1a", publicAddress.getFinalKeyData().getEvmAddress());
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xA3767911A84bE6907f26C572bc89426dDdDB2825",
                        "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
                        "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1"),
                new FinalPubKeyData("0x3507F0d192a44E436B8a6C32a37d57D022861b1a",
                        "8aaadab9530cb157d0b0dfb7b27d1a3aaca45274563c22c92c77ee2191779051",
                        "d57b89d9f62bb6609d8542c3057943805c8c72f6f27d39781b820f27d7210f12"),
                new Metadata(publicAddress.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("tkey-google-cyan", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x3507F0d192a44E436B8a6C32a37d57D022861b1a", key.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v2, key.getMetadata().getTypeOfUser());
        assertThat(key).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xA3767911A84bE6907f26C572bc89426dDdDB2825",
                        "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a",
                        "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1"),
                new FinalPubKeyData("0x3507F0d192a44E436B8a6C32a37d57D022861b1a",
                        "8aaadab9530cb157d0b0dfb7b27d1a3aaca45274563c22c92c77ee2191779051",
                        "d57b89d9f62bb6609d8542c3057943805c8c72f6f27d39781b820f27d7210f12"),
                new Metadata(key.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));

        String v2Verifier = "tkey-google-cyan";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2TestEmail, "")).get();
        assertThat(key2).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x29446f428293a4E6470AEaEDa6EAfA0F842EF54e",
                        "8b6f2048aba8c7833e3b02c5b6522bb18c484ad0025156e428f17fb8d8c34021",
                        "cd9ba153ff89d665f655d1be4c6912f3ff93996e6fe580d89e78bf1476fef2aa"),
                new FinalPubKeyData("0x8EA83Ace86EB414747F2b23f03C38A34E0217814",
                        "cbe7b0f0332e5583c410fcacb6d4ff685bec053cfd943ac75f5e4aa3278a6fbb",
                        "b525c463f438c7a3c4b018c8c5d16c9ef33b9ac6f319140a22b48b17bdf532dd"),
                new Metadata(new GetOrSetNonceResult.PubNonce("da0039dd481e140090bed9e777ce16c0c4a16f30f47e8b08b73ac77737dd2d4",
                        "7fecffd2910fa47dbdbc989f5c119a668fc922937175974953cbb51c49268265"
                ), BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
        assertEquals("0x8EA83Ace86EB414747F2b23f03C38A34E0217814", key2.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v2, key2.getMetadata().getTypeOfUser());

        // 2/n user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2nTestEmail, "")).get();
        assertThat(key3).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xe8a19482cbe5FaC896A5860Ca4156fb999DDc73b",
                        "c491ba39155594896b27cf71a804ccf493289d918f40e6ba4d590f1c76139e9e",
                        "d4649ed9e46461e1af00399a4c65fabb1dc219b3f4af501a7d635c17f57ab553"),
                new FinalPubKeyData("0xCC1f953f6972a9e3d685d260399D6B85E2117561",
                        "8d784434becaad9b23d9293d1f29c4429447315c4cac824cbf2eb21d3f7d79c8",
                        "fe46a0ef5efe33d16f6cfa678a597be930fbec5432cbb7f3580189c18bd7e157"),
                new Metadata(new GetOrSetNonceResult.PubNonce("50e250cc6ac1d50d32d2b0f85f11c6625a917a115ced4ef24f4eac183e1525c7",
                        "8067a52d02b8214bf82e91b66ce5009f674f4c3998b103059c46c386d0c17f90"
                ), BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
        assertEquals("0xCC1f953f6972a9e3d685d260399D6B85E2117561", key3.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v2, key3.getMetadata().getTypeOfUser());
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("tkey-google-cyan", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs("tkey-google-cyan", email, "")).get();
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getEvmAddress(), "");
        assertNotNull(publicAddress.getoAuthKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getoAuthKeyData().getEvmAddress(), "");
        assertFalse(publicAddress.getMetadata().isUpgraded());
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException, TorusException {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs)).get();
        System.out.println(retrieveSharesResponse.getFinalKeyData().getPrivKey());
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
                        "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
                        "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
                        "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8"),
                new OAuthKeyData("0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9",
                        "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1",
                        "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359",
                        "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8"),
                new SessionData(new ArrayList<>(), retrieveSharesResponse.getSessionData().getSessionAuthKey()),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_AGGREGATE_VERIFIER, new HashMap<String, Object>() {{
            put("verify_params", new VerifyParams[]{new VerifyParams(idToken, TORUS_TEST_EMAIL)});
            put("sub_verifier_ids", new String[]{TORUS_TEST_VERIFIER});
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, hashedIdToken).get();
        assertEquals("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04", retrieveSharesResponse.getoAuthKeyData().getEvmAddress());
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04",
                        "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223",
                        "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd",
                        "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf"),
                new OAuthKeyData("0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04",
                        "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223",
                        "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd",
                        "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf"),
                new SessionData(new ArrayList<>(), retrieveSharesResponse.sessionData.sessionAuthKey),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }
}
