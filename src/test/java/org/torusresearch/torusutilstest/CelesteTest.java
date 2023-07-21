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

public class CelesteTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws ExecutionException, InterruptedException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Startingg");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.CELESTE);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.CELESTE.toString());
        opts.setAllowHost("https://signer-polygon.tor.us/api/allow");
        opts.setSignerHost("https://signer-polygon.tor.us/api/sign");
        opts.setClientId("BE4QJC39vkx56M_CaOZFGYuTKve17TpYta9ABSjHWBS_Z1MOMOhOYnjrQDT9YGXJXZvSXM6JULzzukqUB_7a5X0");
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("tkey-google-celeste", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242", publicAddress.getFinalKeyData().getEvmAddress());
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
                        "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
                        "85bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e"),
                new FinalPubKeyData("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
                        "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
                        "85bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("tkey-google-celeste", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242", key.getFinalKeyData().getEvmAddress());
        assertEquals("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242", key.getoAuthKeyData().getEvmAddress());
        assertThat(key).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
                        "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
                        "85bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e"),
                new FinalPubKeyData("0xeC80FB9aB308Be1789Bd3f9317962D5505A4A242",
                        "d1a99fbec9326f04687daea4261b15b68cc45671554d43e94529d62857bf236c",
                        "85bc72609f474b7b80081ecdc92d0dca241327195c7655c7a35b601c1f93e8e"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));

        String v2Verifier = "tkey-google-celeste";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2TestEmail, "")).get();
        assertEquals("0x69fB3A96016817F698a1279aE2d65F3916F3Db6F", key2.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v1, key2.getMetadata().getTypeOfUser());
        assertThat(key2).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x69fB3A96016817F698a1279aE2d65F3916F3Db6F",
                        "9180a724488c99d7639f886e1920598618c2e599481d71ffd9f602c8a856ff20",
                        "c5da5c13fedf3a22964ab39afb871bff607479e2a5cb2e621608771b4276b44b"),
                new FinalPubKeyData("0x69fB3A96016817F698a1279aE2d65F3916F3Db6F",
                        "9180a724488c99d7639f886e1920598618c2e599481d71ffd9f602c8a856ff20",
                        "c5da5c13fedf3a22964ab39afb871bff607479e2a5cb2e621608771b4276b44b"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));

        // 2/n user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2nTestEmail, "")).get();
        assertEquals("0x24aCac36F8A4bD93052207dA410dA71AF92258b7", key3.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v1, key3.getMetadata().getTypeOfUser());
        assertThat(key3).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x24aCac36F8A4bD93052207dA410dA71AF92258b7",
                        "95b242e13e394e252d9685bfc1937a2acfa25e0c5e1d37bfd5247879ae1468cc",
                        "687a6754180aec931ff65e55a058032107df519334b2f5c6fb1fc5157620a219"),
                new FinalPubKeyData("0x24aCac36F8A4bD93052207dA410dA71AF92258b7",
                        "95b242e13e394e252d9685bfc1937a2acfa25e0c5e1d37bfd5247879ae1468cc",
                        "687a6754180aec931ff65e55a058032107df519334b2f5c6fb1fc5157620a219"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("tkey-google-celeste", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs("tkey-google-celeste", email, "")).get();
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
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x58420FB83971C4490D8c9B091f8bfC890D716617",
                        "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
                        "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
                        "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914"),
                new OAuthKeyData("0x58420FB83971C4490D8c9B091f8bfC890D716617",
                        "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74",
                        "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1",
                        "ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914"),
                new SessionData(new ArrayList<>(), ""),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
        assertEquals("0x58420FB83971C4490D8c9B091f8bfC890D716617", retrieveSharesResponse.getFinalKeyData().getEvmAddress());
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException, TorusException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_AGGREGATE_VERIFIER, new HashMap<String, Object>() {{
            put("verify_params", new VerifyParams[]{new VerifyParams(idToken, TORUS_TEST_EMAIL)});
            put("sub_verifier_ids", new String[]{TORUS_TEST_VERIFIER});
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, hashedIdToken).get();
        assertEquals("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564", retrieveSharesResponse.getoAuthKeyData().getEvmAddress());
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
                        "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
                        "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
                        "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e"),
                new OAuthKeyData("0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564",
                        "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca",
                        "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb",
                        "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e"),
                new SessionData(new ArrayList<>(), ""),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }
}

