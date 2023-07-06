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
    static void setup() throws ExecutionException, InterruptedException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.AQUA, FetchNodeDetails.PROXY_ADDRESS_AQUA);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork("aqua");
        opts.setSignerHost("https://signer-polygon.tor.us/api/sign");
        opts.setAllowHost("https://signer-polygon.tor.us/api/allow");
        opts.setClientId("BE4QJC39vkx56M_CaOZFGYuTKve17TpYta9ABSjHWBS_Z1MOMOhOYnjrQDT9YGXJXZvSXM6JULzzukqUB_7a5X0");
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
        assertEquals("0xDfA967285AC699A70DA340F60d00DB19A272639d", publicAddress.getFinalPubKeyData().getEvmAddress());
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xDfA967285AC699A70DA340F60d00DB19A272639d",
                        "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
                        "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c"),
                new FinalPubKeyData("0xDfA967285AC699A70DA340F60d00DB19A272639d",
                        "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d",
                        "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
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
        System.out.println(email + " -> " + publicAddress.getFinalPubKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalPubKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalPubKeyData().getEvmAddress(), "");
        assertNotNull(publicAddress.getoAuthPubKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getoAuthPubKeyData().getEvmAddress(), "");
        assertEquals(publicAddress.getMetadata().getTypeOfUser(), TypeOfUser.v1);
        assertEquals(publicAddress.getMetadata().isUpgraded(), false);
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException, TorusException {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(),
                nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
                    put("verifier_id", TORUS_TEST_EMAIL);
                }},
                JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs)).get();
        System.out.println(retrieveSharesResponse.getFinalKeyData().getPrivKey());
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xdF92B73352Eb4aBd0385bc1e31a8b0BD6EA4D161",
                        "45151049626334797959122802548866520276763178585564784364986393863189010875045",
                        "56424055808696084034226309171000882700166114824429869880517503869697125990463",
                        "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d"),
                new OAuthKeyData("0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195",
                        "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664",
                        "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f",
                        "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d"),
                new SessionData(new ArrayList<>(), ""),
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
                new FinalKeyData("0x011C64d5585E0a34Ca2E70AA0bd34daFC683B358",
                        "38590796519188980875468267478199668365197289821125554170604841336730940042946",
                        "32120738633526637982361662047914076954580011956651434724359038836918748645936",
                        "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355"),
                new OAuthKeyData("0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D",
                        "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d",
                        "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10",
                        "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355"),
                new SessionData(new ArrayList<>(), ""),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }
}

