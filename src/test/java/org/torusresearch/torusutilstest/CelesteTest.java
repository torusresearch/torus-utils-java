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

public class CelesteTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, TorusUtilError {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(Web3AuthNetwork.CELESTE);
        TorusOptions opts = new TorusOptions("YOUR_CLIENT_ID", Web3AuthNetwork.CELESTE, null, 0, false);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(),
                privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("tkey-google-celeste", TORUS_TEST_EMAIL).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), "tkey-google-celeste", TORUS_TEST_EMAIL, null);
        assertTrue(publicAddress.getMetadata().getServerTimeOffset() < 20);
        assertEquals("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113", publicAddress.getFinalKeyData().getWalletAddress());
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
                        "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
                        "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb"),
                new FinalPubKeyData("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
                        "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
                        "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb"),
                new Metadata(publicAddress.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v1, false, publicAddress.getMetadata().getServerTimeOffset()),
                new NodesData(publicAddress.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("tkey-google-celeste", TORUS_TEST_EMAIL).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), "tkey-google-celeste", TORUS_TEST_EMAIL, null);
        assertEquals("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113", key.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v1, key.getMetadata().getTypeOfUser());
        assertThat(key).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
                        "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
                        "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb"),
                new FinalPubKeyData("0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113",
                        "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9",
                        "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb"),
                new Metadata(key.getMetadata().getPubNonce(), BigInteger.ZERO, TypeOfUser.v1, false, key.getMetadata().getServerTimeOffset()),
                new NodesData(key.getNodesData().getNodeIndexes())
        ));

        String v2Verifier = "tkey-google-celeste";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), v2Verifier, v2TestEmail, null);
        assertEquals("0x8d69CE354DA39413f205FdC8680dE1F3FBBb36e2", key2.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key2.getMetadata().getTypeOfUser());
        assertThat(key2).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xda4afB35493094Dd2C05b186Ca0FABAD96491B21",
                        "cfa646a2949ebe559205c5c407d734d1b6927f2ea5fbeabfcbc31ab9a985a336",
                        "8f988eb8b59515293820aa38af172b153e8d25307db8d5f410407c20e062b6e6"),
                new FinalPubKeyData("0x8d69CE354DA39413f205FdC8680dE1F3FBBb36e2",
                        "5962144e03b993b0e503eb4e6e0196427f9fc9472f0dfd1be2ca5d4939f91680",
                        "f6e81f01f483110badab18371237d15834f9ecf31c3588c165dae32ec446ac38"),
                new Metadata(new PubNonce("2f630074151394ba1f715986a9215f4e36c9f22fc264ff880ef6d162c1300aa8",
                        "704cb63e5f7a291735c54e22242ef53673642ec1660da00f1abc2e7909da03d7"),
                        BigInteger.ZERO, TypeOfUser.v2,
                        false,
                        key2.getMetadata().getServerTimeOffset()),
                new NodesData(key2.getNodesData().getNodeIndexes())
        ));

        // 2/n user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), v2Verifier, v2nTestEmail, null);
        assertEquals("0x8108c29976C458e76f797AD55A3715Ce80a3fe78", key3.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, key3.getMetadata().getTypeOfUser());
        assertThat(key3).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xc8c4748ec135196fb482C761da273C31Ec48B099",
                        "0cc857201e6c304dd893b243e323fe95982e5a99c0994cf902efa2432a672eb4",
                        "37a2f53c250b3e1186e38ece3dfcbcb23e325913038703531831b96d3e7b54cc"),
                new FinalPubKeyData("0x8108c29976C458e76f797AD55A3715Ce80a3fe78",
                        "e95fe2d595ade03f56d9c9a147fbb67705041704f147576fa4a8afbe7dc69470",
                        "3e20e4b331466769c4dd78f4561bfb2849010b4005b09c2ed082380326724ebe"),
                new Metadata(new PubNonce("f8ff2c44cc0abf512d35b35c3c5cbc0eda700d49bc13b72c5492b0cdb2ca3619",
                        "88fb3087cec269c8c39d25b04f15298d33712f13b0f9665821328dfc7a567afb"), BigInteger.ZERO,
                        TypeOfUser.v2, false, key3.getMetadata().getServerTimeOffset()),
                new NodesData(key3.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws Exception {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("tkey-google-celeste", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(),
                "tkey-google-celeste", email, "");
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
        TorusKey torusKey = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), TORUS_TEST_VERIFIER, verifierParams,
                JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs), null);
        assertTrue(torusKey.getMetadata().getServerTimeOffset() < 20);
        assert ((torusKey.getFinalKeyData().getWalletAddress() != null) && torusKey.getFinalKeyData().getWalletAddress().equals("0x58420FB83971C4490D8c9B091f8bfC890D716617"));
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x58420FB83971C4490D8c9B091f8bfC890D716617",
                        "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
                        "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
                        "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914"),
                new OAuthKeyData("0x58420FB83971C4490D8c9B091f8bfC890D716617",
                        "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
                        "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
                        "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914"),
                new SessionData(torusKey.getSessionData().getSessionTokenData(), torusKey.getSessionData().getSessionAuthKey()),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, null, torusKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).replace("0x", "");
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, new String[]{TORUS_TEST_VERIFIER}, new VerifyParams[]{new VerifyParams(TORUS_TEST_EMAIL, idToken)});
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        TorusKey torusKey = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), TORUS_TEST_AGGREGATE_VERIFIER, verifierParams,
                hashedIdToken, null);
        assertTrue(torusKey.getMetadata().getServerTimeOffset() < 20);
        assertEquals("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564", torusKey.getoAuthKeyData().getWalletAddress());
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
                        "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
                        "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
                        "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e"),
                new OAuthKeyData("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
                        "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
                        "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
                        "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e"),
                new SessionData(torusKey.getSessionData().getSessionTokenData(), torusKey.getSessionData().getSessionAuthKey()),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, null, torusKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusKey.getNodesData().getNodeIndexes())
        ));
    }
}
