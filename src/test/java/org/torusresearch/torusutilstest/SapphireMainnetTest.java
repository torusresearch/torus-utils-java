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

public class SapphireMainnetTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-aggregate-sapphire-mainnet";

    static String TORUS_IMPORT_EMAIL = "importeduser5@tor.us";
    static String TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";
    static String HashEnabledVerifier = "torus-test-verifierid-hash";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.SAPPHIRE_MAINNET);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.SAPPHIRE_MAINNET.toString());
        opts.setClientId("BLuMSgycHD7DfSvbmN3ISZ5WkdpIjtByKi_cD9ASg_NS3jUYmrrH-dMuJU16z11cev5YocCWLAjWVfq95tFlOD8");
        opts.setEnableOneKey(true);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        String verifier = "tkey-google-sapphire-mainnet";
        VerifierArgs args = new VerifierArgs(verifier, TORUS_TEST_EMAIL, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0x327b2742768B436d09153429E762FADB54413Ded", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xb1a49C6E50a1fC961259a8c388EAf5953FA5152b",
                        "a9f5a463aefb16e90f4cbb9de4a5b6b7f6c6a3831cefa0f20cccb9e7c7b01c20",
                        "3376c6734da57ab3a67c7792eeea20707d16992dd2c827a59499f4c056b00d08"),
                new FinalPubKeyData("0x327b2742768B436d09153429E762FADB54413Ded",
                        "1567e030ca76e520c180c50bc6baed07554ebc35c3132495451173e9310d8be5",
                        "123c0560757ffe6498bf2344165d0f295ea74eb8884683675e5f17ae7bb41cdb"),
                new Metadata(new GetOrSetNonceResult.PubNonce("56e803db7710adbfe0ecca35bc6a3ad27e966df142e157e76e492773c88e8433",
                        "f4168594c1126ca731756dd480f992ee73b0834ba4b787dd892a9211165f50a3"),
                        new BigInteger("f3ba568eeeaca5c285b25878a067fd85b1720b94f9099591d4274dc0a8cada9b", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String verifier = "tkey-google-sapphire-mainnet";
        String email = JwtUtils.getRandomEmail();
        VerifierArgs args = new VerifierArgs(verifier, email, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey result = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertNotEquals("", result.finalKeyData.evmAddress);
        assertNotNull(result.finalKeyData.evmAddress);
        assertNotEquals("", result.finalKeyData.evmAddress);
        assertNotNull(result.finalKeyData.evmAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertFalse(result.metadata.upgraded);
    }

    @DisplayName("should assign key to tss verifier id")
    @Test
    public void shouldAssignKeyToTssVerifierId() throws Exception {
        String email = JwtUtils.getRandomEmail();
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        VerifierArgs verifierArgs = new VerifierArgs(TORUS_TEST_VERIFIER, email, tssVerifierId);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        TorusPublicKey result = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), verifierArgs).get();
        assertNotNull(result.finalKeyData.evmAddress);
        assertNotNull(result.oAuthKeyData.evmAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertFalse(result.metadata.upgraded);
    }

    @DisplayName("should allow test tss verifier id to fetch shares")
    @Test
    public void shouldAllowTestTssVerifierIdToFetchShares() throws ExecutionException, InterruptedException, TorusException {
        String email = JwtUtils.getRandomEmail();
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        String idToken = JwtUtils.generateIdToken(email, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        RetrieveSharesResponse result = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("extended_verifier_id", tssVerifierId);
            put("verifier_id", email);
        }}, idToken).get();
        assertNotNull(result.finalKeyData.privKey);
        assertNotNull(result.oAuthKeyData.evmAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertEquals(BigInteger.ZERO, result.metadata.nonce);
        assertTrue(result.metadata.upgraded);
    }

    @DisplayName("should fetch public address when verifierID hash enabled")
    @Test
    public void shouldFetchPubAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c"),
                new FinalPubKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90"),
                new Metadata(new GetOrSetNonceResult.PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("3c2b6ba5b54ca0ba4ae978eb48429a84c47b7b3e526b35e7d46dd716887f52bf", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("should fetch user type and public address when verifierID hash enabled")
    @Test
    public void shouldFetchUserTypeAndPubAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c"),
                new FinalPubKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90"),
                new Metadata(new GetOrSetNonceResult.PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("3c2b6ba5b54ca0ba4ae978eb48429a84c47b7b3e526b35e7d46dd716887f52bf", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("should be able to login when verifierID hash enabled")
    @Test
    public void testShouldBeAbleToLoginWhenVerifierIdHashEnabled() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), HashEnabledVerifier, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, idToken).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("13941ecd812b08d8a33a20bc975f0cd1c3f82de25b20c0c863ba5f21580b65f6"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90",
                        "13941ecd812b08d8a33a20bc975f0cd1c3f82de25b20c0c863ba5f21580b65f6"),
                new OAuthKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c",
                        "d768b327cbde681e5850a7d14f1c724bba2b8f8ab7fe2b1c4f1ee6979fc25478"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("3c2b6ba5b54ca0ba4ae978eb48429a84c47b7b3e526b35e7d46dd716887f52bf", 16), TypeOfUser.v2,
                        false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("should be able to login")
    @Test
    public void shouldBeAbleToLogin() throws ExecutionException, InterruptedException, TorusException {
        String token = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, token).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("dfb39b84e0c64b8c44605151bf8670ae6eda232056265434729b6a8a50fa3419"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x70520A7F04868ACad901683699Fa32765C9F6871",
                        "adff099b5d3b1e238b43fba1643cfa486e8d9e8de22c1e6731d06a5303f9025b",
                        "21060328e7889afd303acb63201b6493e3061057d1d81279931ab4a6cabf94d4",
                        "dfb39b84e0c64b8c44605151bf8670ae6eda232056265434729b6a8a50fa3419"),
                new OAuthKeyData("0x925c97404F1aBdf4A8085B93edC7B9F0CEB3C673",
                        "5cd8625fc01c7f7863a58c914a8c43b2833b3d0d5059350bab4acf6f4766a33d",
                        "198a4989615c5c2c7fa4d49c076ea7765743d09816bb998acb9ff54f5db4a391",
                        "90a219ac78273e82e36eaa57c15f9070195e436644319d6b9aea422bb4d31906"),
                new SessionData(retrieveSharesResponse.getSessionData().getSessionTokenData(), retrieveSharesResponse.getSessionData().getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce("ab4d287c263ab1bb83c37646d0279764e50fe4b0c34de4da113657866ddcf318",
                        "ad35db2679dfad4b62d77cf753d7b98f73c902e5d101cc2c3c1209ece6d94382"),
                        new BigInteger("4f1181d8689f0d0960f1a6f9fe26e03e557bdfba11f4b6c8d7b1285e9c271b13", 16),
                        TypeOfUser.v2, false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("should be able to aggregate login")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException, TorusException {
        String email = JwtUtils.getRandomEmail();
        String idToken = JwtUtils.generateIdToken(email, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, email).get();
        RetrieveSharesResponse result = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_AGGREGATE_VERIFIER, new HashMap<String, Object>() {{
            put("verify_params", new VerifyParams[]{new VerifyParams(idToken, email)});
            put("sub_verifier_ids", new String[]{TORUS_TEST_VERIFIER});
            put("verifier_id", email);
        }}, hashedIdToken).get();
        assertNotNull(result.finalKeyData.evmAddress);
        assertNotNull(result.oAuthKeyData.evmAddress);
        assertEquals(TypeOfUser.v2, result.metadata.typeOfUser);
        assertNotNull(result.metadata.nonce);
    }

    @DisplayName("Should fetch user type and public address when verifierID hash enabled")
    @Test
    public void testFetchUserTypeAndPublicAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c"),
                new FinalPubKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90"),
                new Metadata(new GetOrSetNonceResult.PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("3c2b6ba5b54ca0ba4ae978eb48429a84c47b7b3e526b35e7d46dd716887f52bf", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    /*@DisplayName("should be able to import a key for a new user")
    @Test
    public void shouldImportKeyForNewUser() throws Exception {
        String email = JwtUtils.getRandomEmail();
        String idToken = JwtUtils.generateIdToken(email, algorithmRs);
        String privHex = Utils.generatePrivate().toString(16);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        RetrieveSharesResponse response = torusUtils.importPrivateKey(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(),
                nodeDetails.getTorusNodePub(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
                    put("verifier_id", email);
                }}, idToken, privHex, null).get();
        assertEquals(response.finalKeyData.privKey, privHex);
    }

    @DisplayName("hould be able to import a key for a existing user")
    @Test
    public void shouldImportKeyForExistingUser() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_VERIFIER, algorithmRs);
        String privHex = Utils.generatePrivate().toString(16);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_IMPORT_EMAIL).get();
        RetrieveSharesResponse response = torusUtils.importPrivateKey(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(),
                nodeDetails.getTorusNodePub(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
                    put("verifier_id", TORUS_IMPORT_EMAIL);
                }}, idToken, privHex, null).get();
        assertEquals(response.finalKeyData.privKey, privHex);
        TorusPublicKey publicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(),
                new VerifierArgs(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL)).get();
        assertEquals(response.finalKeyData.evmAddress, publicKey.getFinalKeyData().getEvmAddress());
    }*/
}
