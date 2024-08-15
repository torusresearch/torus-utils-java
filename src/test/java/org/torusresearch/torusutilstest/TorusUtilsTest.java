package org.torusresearch.torusutilstest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auth0.jwt.algorithms.Algorithm;

import org.junit.jupiter.api.BeforeEach;
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
import org.torusresearch.torusutils.types.common.PubNonce;
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

public class TorusUtilsTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "archit1@tor.us";

    @BeforeEach
    void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, TorusUtilError {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(Web3AuthNetwork.TESTNET);
        TorusOptions opts = new TorusOptions("YOUR_CLIENT_ID", Web3AuthNetwork.TESTNET, null, 0, false);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google-lrc", TORUS_TEST_EMAIL).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), "google-lrc", TORUS_TEST_EMAIL, null);
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
                        "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
                        "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438"),
                new FinalPubKeyData("0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
                        "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
                        "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438"),
                new Metadata(publicAddress.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v1, false, publicAddress.getMetadata().getServerTimeOffset()),
                new NodesData(publicAddress.getNodesData().getNodeIndexes())
        ));
        assertTrue(publicAddress.getMetadata().getServerTimeOffset() < 20);
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google-lrc", TORUS_TEST_EMAIL).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), "google-lrc", TORUS_TEST_EMAIL, null);
        assertThat(key).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x9bcBAde70546c0796c00323CD1b97fa0a425A506",
                        "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5",
                        "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438"),
                new FinalPubKeyData("0xf5804f608C233b9cdA5952E46EB86C9037fd6842",
                        "ed737569a557b50722a8b5c0e4e5ca30cef1ede2f5674a0616b78246bb93dfd0",
                        "d9e8e6c54c12c4da38c2f0d1047fcf6089036127738f4ef72a83431339586ca9"),
                new Metadata(new PubNonce("f3f7caefd6540d923c9993113f34226371bd6714a5be6882dedc95a6a929a8",
                        "f28620603601ce54fa0d70fd691fb72ff52f5bf164bf1a91617922eaad8cc7a5"),
                        BigInteger.ZERO, TypeOfUser.v2, false, key.getMetadata().getServerTimeOffset()),
                new NodesData(key.getNodesData().getNodeIndexes())
        ));
        assertEquals("0xf5804f608C233b9cdA5952E46EB86C9037fd6842", key.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key.getMetadata().getTypeOfUser());

        String v2Verifier = "tkey-google-lrc";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), v2Verifier, v2TestEmail, null);
        assertThat(key2).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x376597141d8d219553378313d18590F373B09795",
                        "86cd2db15b7a9937fa8ab7d0bf8e7f4113b64d1f4b2397aad35d6d4749d2fb6c",
                        "86ef47a3724144331c31a3a322d85b6fc1a5d113b41eaa0052053b6e3c74a3e2"),
                new FinalPubKeyData("0xE91200d82029603d73d6E307DbCbd9A7D0129d8D",
                        "c350e338dde24df986915992fea6e0aef3560c245ca144ee7fe1498784c4ef4e",
                        "a605e52b65d3635f89654519dfa7e31f7b45f206ef4189866ad0c2240d40f97f"),
                new Metadata(new PubNonce("ad121b67fa550da814bbbd54ec7070705d058c941e04c03e07967b07b2f90345",
                        "bfe2395b177a72ebb836aaf24cedff2f14cd9ed49047990f5cdb99e4981b5753"),
                        BigInteger.ZERO, TypeOfUser.v2, false, key2.getMetadata().getServerTimeOffset()),
                new NodesData(key2.getNodesData().getNodeIndexes())
        ));
        assertEquals("0xE91200d82029603d73d6E307DbCbd9A7D0129d8D", key2.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key2.getMetadata().getTypeOfUser());

        // 2/n user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), v2Verifier, v2nTestEmail, null);
        assertThat(key3).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xd45383fbF04BccFa0450d7d8ee453ca86b7C6544",
                        "d25cc473fbb448d20b5551f3c9aa121e1924b3d197353347187c47ad13ecd5d8",
                        "3394000f43160a925e6c3017dde1354ecb2b61739571c6584f58edd6b923b0f5"),
                new FinalPubKeyData("0x1016DA7c47A04C76036637Ea02AcF1d29c64a456",
                        "d3e222f6b23f0436b7c86e9cc4164eb5ea8448e4c0e7539c8b4f7fd00e8ec5c7",
                        "1c47f5faccec6cf57c36919f6f0941fe3d8d65033cf2cc78f209304386044222"),
                new Metadata(new PubNonce("4f86b0e69992d1551f1b16ceb0909453dbe17b9422b030ee6c5471c2e16b65d0",
                        "640384f3d39debb04c4e9fe5a5ec6a1b494b0ad66d00ac9be6f166f21d116ca4"),
                        BigInteger.ZERO, TypeOfUser.v2, true, key3.getMetadata().getServerTimeOffset()),
                new NodesData(key3.getNodesData().getNodeIndexes())
        ));
        assertEquals("0x1016DA7c47A04C76036637Ea02AcF1d29c64a456", key3.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key3.getMetadata().getTypeOfUser());
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws Exception {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google-lrc", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), "google-lrc", email, "");
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getWalletAddress());
        assertNotNull(publicAddress.getFinalKeyData().getWalletAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getWalletAddress(), "");
        assertNotNull(publicAddress.getoAuthKeyData().getWalletAddress());
        assertNotEquals(publicAddress.getoAuthKeyData().getWalletAddress(), "");
        assertEquals(publicAddress.getMetadata().getTypeOfUser(), TypeOfUser.v2);
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
        assert ((torusKey.getFinalKeyData().getPrivKey() != null) && torusKey.getFinalKeyData().getPrivKey().equals("9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3"));
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6",
                        "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd",
                        "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9",
                        "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3"),
                new OAuthKeyData("0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6",
                        "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd",
                        "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9",
                        "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3"),
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
        assertEquals("0x938a40E155d118BD31E439A9d92D67bd55317965", torusKey.getoAuthKeyData().getWalletAddress());
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x938a40E155d118BD31E439A9d92D67bd55317965",
                        "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95",
                        "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6",
                        "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1"),
                new OAuthKeyData("0x938a40E155d118BD31E439A9d92D67bd55317965",
                        "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95",
                        "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6",
                        "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1"),
                new SessionData(torusKey.getSessionData().getSessionTokenData(), torusKey.getSessionData().getSessionAuthKey()),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, null, torusKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusKey.getNodesData().getNodeIndexes())
        ));
    }
}
