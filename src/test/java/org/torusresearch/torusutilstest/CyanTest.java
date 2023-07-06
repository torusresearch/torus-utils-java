package org.torusresearch.torusutilstest;

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
import org.torusresearch.torusutils.types.RetrieveSharesResponse;
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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
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
        VerifierArgs args = new VerifierArgs("tkey-google-cyan", TORUS_TEST_EMAIL, "extendedVerifierId");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xA3767911A84bE6907f26C572bc89426dDdDB2825", publicAddress.getFinalPubKeyData().getEvmAddress());
    }

    @DisplayName("Fetch User Type and Public Address")
    @Test
    public void shouldFetchUserTypeAndPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("tkey-google-cyan", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey key = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xA3767911A84bE6907f26C572bc89426dDdDB2825", key.getFinalPubKeyData().getEvmAddress());
        assertEquals(TypeOfUser.v1, key.getMetadata().getTypeOfUser());

        String v2Verifier = "tkey-google-cyan";
        // 1/1 user
        String v2TestEmail = "somev2user@gmail.com";
        TorusPublicKey key2 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2TestEmail, "")).get();
        //assertEquals("0x8EA83Ace86EB414747F2b23f03C38A34E0217814", key2.getFinalPubKeyData().getEvmAddress());
        //assertEquals(TypeOfUser.v2, key2.getMetadata().getTypeOfUser());

        // 2/n user
        String v2nTestEmail = "caspertorus@gmail.com";
        TorusPublicKey key3 = torusUtils.getUserTypeAndAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(v2Verifier, v2nTestEmail, "")).get();
        //assertEquals("0xCC1f953f6972a9e3d685d260399D6B85E2117561", key3.getFinalPubKeyData().getEvmAddress());
        //assertEquals(TypeOfUser.v2, key3.getMetadata().getTypeOfUser());
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("tkey-google-cyan", email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs("tkey-google-cyan", email, "extendedVerifierId")).get();
        System.out.println(email + " -> " + publicAddress.getFinalPubKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalPubKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalPubKeyData().getEvmAddress(), "");
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException, TorusException {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs)).get();
        System.out.println(retrieveSharesResponse.getFinalKeyData().getPrivKey());
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("1e0c955d73e73558f46521da55cc66de7b8fcb56c5b24e851616849b6a1278c8"));
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
    }
}
