package org.torusresearch.torusutilstest;

import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.EthereumNetwork;
import org.torusresearch.fetchnodedetails.types.NodeDetails;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.types.RetrieveSharesResponse;
import org.torusresearch.torusutils.types.TorusException;
import org.torusresearch.torusutils.types.TorusPublicKey;
import org.torusresearch.torusutils.types.VerifierArgs;
import org.torusresearch.torusutilstest.utils.JwtUtils;
import org.torusresearch.torusutilstest.utils.PemUtils;
import org.torusresearch.torusutilstest.utils.VerifyParams;
import org.web3j.crypto.Hash;
import sun.security.rsa.RSAPrivateCrtKeyImpl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TorusUtilsTest {

    static NodeDetails nodeDetails;

    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws ExecutionException, InterruptedException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        FetchNodeDetails fetchNodeDetails = new FetchNodeDetails(EthereumNetwork.ROPSTEN, "0x4023d2a0D330bF11426B12C6144Cfb96B7fa6183");
        nodeDetails = fetchNodeDetails.getNodeDetails().get();
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "RSA");
        RSAPrivateCrtKeyImpl rsaPrivateKey = (RSAPrivateCrtKeyImpl) privateKey;
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent()));
        algorithmRs = Algorithm.RSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("google-lrc", TORUS_TEST_EMAIL);
        System.out.println("Starting test");
        Arrays.stream(nodeDetails.getTorusNodeEndpoints()).forEach(System.out::println);
        Arrays.stream(nodeDetails.getTorusNodePub()).forEach(System.out::println);
        TorusUtils torusUtils = new TorusUtils();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        System.out.println(publicAddress.getAddress());
        assertEquals("0xFf5aDad69F4e97AF4D4567e7C333C12df6836a70", publicAddress.getAddress());
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        TorusUtils torusUtils = new TorusUtils();
        String email = JwtUtils.getRandomEmail();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(),
                nodeDetails.getTorusNodePub(), new VerifierArgs("google-lrc", email)).get();
        System.out.println(email + " -> " + publicAddress.getAddress());
        assertNotNull(publicAddress.getAddress());
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException, TorusException {
        TorusUtils torusUtils = new TorusUtils();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(),
                nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
                    put("verifier_id", TORUS_TEST_EMAIL);
                }},
                JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs)).get();
        System.out.println(retrieveSharesResponse.getPrivKey());
        BigInteger requiredPrivateKey = new BigInteger("68ee4f97468ef1ae95d18554458d372e31968190ae38e377be59d8b3c9f7a25", 16);
        assert (requiredPrivateKey.equals(new BigInteger(retrieveSharesResponse.getPrivKey(), 16)));
        assertEquals("0xEfd7eDAebD0D99D1B7C8424b54835457dD005Dc4", retrieveSharesResponse.getEthAddress());
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException, TorusException {
        TorusUtils torusUtils = new TorusUtils();
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(),
                nodeDetails.getTorusIndexes(), TORUS_TEST_AGGREGATE_VERIFIER, new HashMap<String, Object>() {{
                    put("verify_params", new VerifyParams[]{
                            new VerifyParams(idToken, TORUS_TEST_EMAIL)
                    });
                    put("sub_verifier_ids", new String[]{TORUS_TEST_VERIFIER});
                    put("verifier_id", TORUS_TEST_EMAIL);
                }},
                hashedIdToken).get();
        System.out.println(retrieveSharesResponse.getEthAddress());
        assertEquals("0x5a165d2Ed4976BD104caDE1b2948a93B72FA91D2", retrieveSharesResponse.getEthAddress());
    }
}
