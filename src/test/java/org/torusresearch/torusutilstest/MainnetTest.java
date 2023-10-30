package org.torusresearch.torusutilstest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.RetrieveSharesResponse;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.TorusCtorOptions;
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

public class MainnetTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.MAINNET);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.MAINNET.toString());
        opts.setAllowHost("https://signer.tor.us/api/allow");
        opts.setClientId("BEaGnq-mY0ZOXk2UT1ivWUe0PZ_iJX4Vyb6MtpOp7RMBu_6ErTrATlfuK3IaFcvHJr27h6L1T4owkBH6srLphIw");
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("google", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A", publicAddress.getFinalKeyData().getEvmAddress());
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
                        "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
                        "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1"),
                new FinalPubKeyData("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
                        "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
                        "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("google", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A", key.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v1, key.getMetadata().getTypeOfUser());
        assertThat(key).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
                        "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
                        "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1"),
                new FinalPubKeyData("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
                        "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
                        "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));

        String v2Verifier = "tkey-google";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2TestEmail, "")).get();
        /*assertEquals("0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526", key2.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v2, key2.getMetadata().getTypeOfUser());
        assertThat(key2).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xA9c6829e4899b6D630130ebf59D046CA868D7f83",
                        "5566cd940ea540ba1a3ba2ff0f5fd3d9a3a74350ac3baf47b811592ae6ea1c30",
                        "07a302e87e8d9eb5d143f570c248657288c13c09ecbe1e3a8720449daf9315b0"),
                new FinalPubKeyData("0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526",
                        "bbfd26b1e61572c4e991a21b64f12b313cb6fce6b443be92d4d5fd8f311e8f33",
                        "df2c905356ec94faaa111a886be56ed6fa215b7facc1d1598486558355123c25"),
                new Metadata(new GetOrSetNonceResult.PubNonce("96f4b7d3c8c8c69cabdea46ae1eedda346b03cad8ba1a454871b0ec6a69861f3",
                        "da3aed7f7e9d612052beb1d92ec68a8dcf60faf356985435b424af2423f66672"),
                        BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));*/

        // v1 user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2nTestEmail, "")).get();
        assertEquals("0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53", key3.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v1, key3.getMetadata().getTypeOfUser());
        assertThat(key3).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53",
                        "c01282dd68d2341031a1cff06f70d821cad45140f425f1c25055a8aa64959df8",
                        "cb3937773bb819d60b780b6d4c2edcf27c0f7090ba1fc2ff42504a8138a8e2d7"),
                new FinalPubKeyData("0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53",
                        "c01282dd68d2341031a1cff06f70d821cad45140f425f1c25055a8aa64959df8",
                        "cb3937773bb819d60b780b6d4c2edcf27c0f7090ba1fc2ff42504a8138a8e2d7"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs("google", email, "")).get();
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getEvmAddress(), "");
        assertNotNull(publicAddress.getoAuthKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getoAuthKeyData().getEvmAddress(), "");
        assertEquals(publicAddress.getMetadata().isUpgraded(), false);
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs)).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x90A926b698047b4A87265ba1E9D8b512E8489067",
                        "a92d8bf1f01ad62e189a5cb0f606b89aa6df1b867128438c38e3209f3b9fc34f",
                        "ad1ffaecb2178b02a37c455975368be9b967ead1b281202cc8d48c77618bff1",
                        "0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44"),
                new OAuthKeyData("0x90A926b698047b4A87265ba1E9D8b512E8489067",
                        "a92d8bf1f01ad62e189a5cb0f606b89aa6df1b867128438c38e3209f3b9fc34f",
                        "0ad1ffaecb2178b02a37c455975368be9b967ead1b281202cc8d48c77618bff1",
                        "129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44"),
                new SessionData(new ArrayList<>(), retrieveSharesResponse.sessionData.sessionAuthKey),
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
        assertEquals("0x621a4d458cFd345dAE831D9E756F10cC40A50381", retrieveSharesResponse.getoAuthKeyData().getEvmAddress());
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x621a4d458cFd345dAE831D9E756F10cC40A50381",
                        "52abc69ebec21deacd273dbdcb4d40066b701177bba906a187676e3292e1e236",
                        "5e57e251db2c95c874f7ec852439302a62ef9592c8c50024e3d48018a6f77c7e",
                        "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534"),
                new OAuthKeyData("0x621a4d458cFd345dAE831D9E756F10cC40A50381",
                        "52abc69ebec21deacd273dbdcb4d40066b701177bba906a187676e3292e1e236",
                        "5e57e251db2c95c874f7ec852439302a62ef9592c8c50024e3d48018a6f77c7e",
                        "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534"),
                new SessionData(new ArrayList<>(), retrieveSharesResponse.sessionData.sessionAuthKey),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }
}
