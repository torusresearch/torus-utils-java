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
import org.torusresearch.fetchnodedetails.types.Web3AuthNetwork;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.helpers.TorusUtilError;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.Metadata;
import org.torusresearch.torusutils.types.NodesData;
import org.torusresearch.torusutils.types.OAuthKeyData;
import org.torusresearch.torusutils.types.OAuthPubKeyData;
import org.torusresearch.torusutils.types.SessionData;
import org.torusresearch.torusutils.types.VerifierParams;
import org.torusresearch.torusutils.types.VerifyParams;
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

public class MainnetTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, TorusUtilError {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(Web3AuthNetwork.MAINNET);
        TorusOptions opts = new TorusOptions("YOUR_CLIENT_ID", Web3AuthNetwork.MAINNET, null, 0, false);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google", TORUS_TEST_EMAIL).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), "google", TORUS_TEST_EMAIL, null);
        assertEquals("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A", publicAddress.getFinalKeyData().getWalletAddress());
        assertTrue(publicAddress.getMetadata().getServerTimeOffset() < 20);
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
                        "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
                        "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1"),
                new FinalPubKeyData("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
                        "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
                        "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1"),
                new Metadata(publicAddress.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v1, false, publicAddress.getMetadata().getServerTimeOffset()),
                new NodesData(publicAddress.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google", TORUS_TEST_EMAIL).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), "google", TORUS_TEST_EMAIL, null);
        assertEquals("0xb2e1c3119f8D8E73de7eaF7A535FB39A3Ae98C5E", key.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key.getMetadata().getTypeOfUser());
        assertThat(key).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A",
                        "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4",
                        "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1"),
                new FinalPubKeyData("0xb2e1c3119f8D8E73de7eaF7A535FB39A3Ae98C5E",
                        "072beda348a832aed06044a258cb6a8d428ec7c245c5da92db5da4f3ab433e55",
                        "54ace0d3df2504fa29f17d424a36a0f92703899fad0afee93d010f6d84b310e5"),
                new Metadata(key.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v2, false, key.getMetadata().getServerTimeOffset()),
                new NodesData(key.getNodesData().getNodeIndexes())
        ));

        String v2Verifier = "tkey-google";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), v2Verifier, v2TestEmail, null);
        assertEquals("0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526", key2.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key2.getMetadata().getTypeOfUser());
        assertThat(key2).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xA9c6829e4899b6D630130ebf59D046CA868D7f83",
                        "5566cd940ea540ba1a3ba2ff0f5fd3d9a3a74350ac3baf47b811592ae6ea1c30",
                        "07a302e87e8d9eb5d143f570c248657288c13c09ecbe1e3a8720449daf9315b0"),
                new FinalPubKeyData("0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526",
                        "bbfd26b1e61572c4e991a21b64f12b313cb6fce6b443be92d4d5fd8f311e8f33",
                        "df2c905356ec94faaa111a886be56ed6fa215b7facc1d1598486558355123c25"),
                new Metadata(key2.getMetadata().getPubNonce(),
                        BigInteger.ZERO, TypeOfUser.v2, false, key2.getMetadata().getServerTimeOffset()),
                new NodesData(key2.getNodesData().getNodeIndexes())
        ));

        // v1 user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), v2Verifier, v2nTestEmail, null);
        assertEquals("0x40A4A04fDa1f29a3667152C8830112FBd6A77BDD", key3.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key3.getMetadata().getTypeOfUser());
        assertThat(key3).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53",
                        "c01282dd68d2341031a1cff06f70d821cad45140f425f1c25055a8aa64959df8",
                        "cb3937773bb819d60b780b6d4c2edcf27c0f7090ba1fc2ff42504a8138a8e2d7"),
                new FinalPubKeyData("0x40A4A04fDa1f29a3667152C8830112FBd6A77BDD",
                        "6779af3031d9e9eec6b4133b0ae13e367c83a614f92d2008e10c7f3b8e6723bc",
                        "80edc4502abdfb220dd6e2fcfa2dbb058125dc95873e4bfa6877f9c26da7fdff"),
                new Metadata(key3.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v2, false, key3.getMetadata().getServerTimeOffset()),
                new NodesData(key3.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws Exception {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), "google", email, "");
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getWalletAddress());
        assertNotNull(publicAddress.getFinalKeyData().getWalletAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getWalletAddress(), "");
        assertNotNull(publicAddress.getoAuthKeyData().getWalletAddress());
        assertNotEquals(publicAddress.getoAuthKeyData().getWalletAddress(), "");
        assertFalse(publicAddress.getMetadata().isUpgraded());
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, null, null);
        TorusKey torusKey = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), TORUS_TEST_VERIFIER,
                verifierParams, JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs), null);
        assertTrue(torusKey.getMetadata().getServerTimeOffset() < 20);
        assert ((torusKey.getFinalKeyData().getPrivKey() != null) && torusKey.getFinalKeyData().getPrivKey().equals("0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44"));
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x90A926b698047b4A87265ba1E9D8b512E8489067",
                        "a92d8bf1f01ad62e189a5cb0f606b89aa6df1b867128438c38e3209f3b9fc34f",
                        "0ad1ffaecb2178b02a37c455975368be9b967ead1b281202cc8d48c77618bff1",
                        "0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44"),
                new OAuthKeyData("0x90A926b698047b4A87265ba1E9D8b512E8489067",
                        "a92d8bf1f01ad62e189a5cb0f606b89aa6df1b867128438c38e3209f3b9fc34f",
                        "0ad1ffaecb2178b02a37c455975368be9b967ead1b281202cc8d48c77618bff1",
                        "0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44"),
                new SessionData(torusKey.getSessionData().getSessionTokenData(), torusKey.getSessionData().getSessionAuthKey()),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, null, torusKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).replace("0x","");
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, new String[]{TORUS_TEST_VERIFIER}, new VerifyParams[]{new VerifyParams(TORUS_TEST_EMAIL, idToken)});
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        TorusKey torusKey = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), TORUS_TEST_AGGREGATE_VERIFIER,
                verifierParams, hashedIdToken, null);
        assertTrue(torusKey.getMetadata().getServerTimeOffset() < 20);
        assertEquals("0x621a4d458cFd345dAE831D9E756F10cC40A50381", torusKey.getoAuthKeyData().getWalletAddress());
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x621a4d458cFd345dAE831D9E756F10cC40A50381",
                        "52abc69ebec21deacd273dbdcb4d40066b701177bba906a187676e3292e1e236",
                        "5e57e251db2c95c874f7ec852439302a62ef9592c8c50024e3d48018a6f77c7e",
                        "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534"),
                new OAuthKeyData("0x621a4d458cFd345dAE831D9E756F10cC40A50381",
                        "52abc69ebec21deacd273dbdcb4d40066b701177bba906a187676e3292e1e236",
                        "5e57e251db2c95c874f7ec852439302a62ef9592c8c50024e3d48018a6f77c7e",
                        "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534"),
                new SessionData(torusKey.getSessionData().getSessionTokenData(), torusKey.getSessionData().getSessionAuthKey()),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, null, torusKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusKey.getNodesData().getNodeIndexes())
        ));
    }
}
