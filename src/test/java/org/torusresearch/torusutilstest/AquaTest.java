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

public class AquaTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.AQUA);
        TorusCtorOptions opts = new TorusCtorOptions("Custom", "BE4QJC39vkx56M_CaOZFGYuTKve17TpYta9ABSjHWBS_Z1MOMOhOYnjrQDT9YGXJXZvSXM6JULzzukqUB_7a5X0");
        opts.setNetwork("aqua");
        opts.setSignerHost("https://signer-polygon.tor.us/api/sign");
        opts.setAllowHost("https://signer-polygon.tor.us/api/allow");
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(),
                privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("tkey-google-aqua", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x79F06350eF34Aeed4BE68e26954D405D573f1438", publicAddress.getFinalKeyData().getEvmAddress());
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xDfA967285AC699A70DA340F60d00DB19A272639d",
                        "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
                        "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c"),
                new FinalPubKeyData("0x79F06350eF34Aeed4BE68e26954D405D573f1438",
                        "99df45abc8e6ee03d2f94df33be79e939eadfbed20c6b88492782fdc3ef1dfd3",
                        "12bf3e54599a177fdb88f8b22419df7ddf1622e1d2344301edbe090890a72b16"),
                new Metadata(publicAddress.getMetadata().pubNonce, BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("tkey-google-aqua", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x79F06350eF34Aeed4BE68e26954D405D573f1438", key.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v2, key.getMetadata().getTypeOfUser());
        assertThat(key).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xDfA967285AC699A70DA340F60d00DB19A272639d",
                        "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
                        "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c"),
                new FinalPubKeyData("0x79F06350eF34Aeed4BE68e26954D405D573f1438",
                        "99df45abc8e6ee03d2f94df33be79e939eadfbed20c6b88492782fdc3ef1dfd3",
                        "12bf3e54599a177fdb88f8b22419df7ddf1622e1d2344301edbe090890a72b16"),
                new Metadata(key.getMetadata().pubNonce, BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));

        String v2Verifier = "tkey-google-aqua";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2TestEmail, "")).get();
        assertEquals("0xBc32f315515AdE7010cabC5Fd68c966657A570BD", key2.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v2, key2.getMetadata().getTypeOfUser());
        assertThat(key2).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x4ea5260fF85678A2a326D08DF9C44d1f559a5828",
                        "e6febe33a9d4eeb680cc6b63ff6237ad1971f27adcd7f104a3b1de18eda9337",
                        "a5a915561f3543688e71281a850b9ee10b9690f305d9e79028dfc8359192b82d"),
                new FinalPubKeyData("0xBc32f315515AdE7010cabC5Fd68c966657A570BD",
                        "4897f120584ee18a72b9a6bb92c3ef6e45fc5fdff70beae7dc9325bd01332022",
                        "2066dbef2fcdded4573e3c04d1c04edd5d44662168e636ed9d0b0cbe2e67c968"),
                new Metadata(key2.getMetadata().pubNonce, BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));

        // 2/n user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2nTestEmail, "")).get();
        assertEquals("0x5469C5aCB0F30929226AfF4622918DA8E1424a8D", key3.getFinalKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v2, key3.getMetadata().getTypeOfUser());
        assertThat(key3).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x4ce0D09C3989eb3cC9372cC27fa022D721D737dD",
                        "e76d2f7fa2c0df324b4ab74629c3af47aa4609c35f1d2b6b90b77a47ab9a1281",
                        "b33b35148d72d357070f66372e07fec436001bdb15c098276b120b9ed64c1e5f"),
                new FinalPubKeyData("0x5469C5aCB0F30929226AfF4622918DA8E1424a8D",
                        "c20fac685bb67169e92f1d5d8894d4eea18753c0ef3b7b1b2224233b2dfa3539",
                        "c4f080b5c8d5c55c8eaba4bec70f668f36db4126f358b491d631fefea7c19d21"),
                new Metadata(key3.getMetadata().pubNonce, BigInteger.ZERO, TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("tkey-google-aqua", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(),
                new VerifierArgs("tkey-google-aqua", email, "")).get();
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getEvmAddress(), "");
        assertNotNull(publicAddress.getoAuthKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getoAuthKeyData().getEvmAddress(), "");
        assertFalse(publicAddress.getMetadata().isUpgraded());
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(),
                nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
                    put("verifier_id", TORUS_TEST_EMAIL);
                }},
                JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs)).get();
        System.out.println(retrieveSharesResponse.getFinalKeyData().getPrivKey());
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195",
                        "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664",
                        "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f",
                        "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d"),
                new OAuthKeyData("0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195",
                        "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664",
                        "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f",
                        "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d"),
                new SessionData(new ArrayList<>(), retrieveSharesResponse.sessionData.sessionAuthKey),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException, TorusException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(),
                nodeDetails.getTorusIndexes(), TORUS_TEST_AGGREGATE_VERIFIER, new HashMap<String, Object>() {{
                    put("verify_params", new VerifyParams[]{
                            new VerifyParams(idToken, TORUS_TEST_EMAIL)
                    });
                    put("sub_verifier_ids", new String[]{TORUS_TEST_VERIFIER});
                    put("verifier_id", TORUS_TEST_EMAIL);
                }},
                hashedIdToken).get();
        assertEquals("0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D", retrieveSharesResponse.getoAuthKeyData().evmAddress);
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D",
                        "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d",
                        "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10",
                        "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355"),
                new OAuthKeyData("0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D",
                        "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d",
                        "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10",
                        "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355"),
                new SessionData(new ArrayList<>(), retrieveSharesResponse.sessionData.sessionAuthKey),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }
}

