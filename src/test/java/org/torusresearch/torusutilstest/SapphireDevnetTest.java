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
import org.torusresearch.torusutils.helpers.Utils;
import org.torusresearch.torusutils.types.FinalKeyData;
import org.torusresearch.torusutils.types.FinalPubKeyData;
import org.torusresearch.torusutils.types.GetOrSetNonceResult;
import org.torusresearch.torusutils.types.ImportedShare;
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

public class SapphireDevnetTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_IMPORT_EMAIL = "importeduser5@tor.us";
    static String TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";
    static String HashEnabledVerifier = "torus-test-verifierid-hash";

    static String TORUS_TEST_EMAIL = "saasas@tr.us";

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.SAPPHIRE_DEVNET);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.SAPPHIRE_DEVNET.toString());
        opts.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
        opts.setEnableOneKey(true);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        String verifier = TORUS_TEST_VERIFIER;
        VerifierArgs args = new VerifierArgs(verifier, TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
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

    @DisplayName("should fetch public address of a legacy v1 user")
    @Test
    public void testFetchPublicAddressOfLegacyV1User() throws ExecutionException, InterruptedException {
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.TESTNET);
        VerifierArgs verifierDetails = new VerifierArgs("google-lrc", "himanshu@tor.us", ""); // Replace with the actual verifier ID
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.TESTNET.toString());
        opts.setAllowHost("https://signer.tor.us/api/allow");
        opts.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
        opts.setEnableOneKey(true);
        torusUtils = new TorusUtils(opts);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails("google-lrc", "himanshu@tor.us").get();
        TorusPublicKey publicKeyData = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), verifierDetails).get();
        assertEquals(TypeOfUser.v1, publicKeyData.getMetadata().getTypeOfUser());
        assertThat(publicKeyData).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xf1e76fcDD28b5AA06De01de508fF21589aB9017E",
                        "b3f2b4d8b746353fe670e0c39ac9adb58056d4d7b718d06b623612d4ec49268b",
                        "ac9f79dff78add39cdba380dbbf517c20cf2c1e06b32842a90a84a31f6eb9a9a"),
                new FinalPubKeyData("0x930abEDDCa6F9807EaE77A3aCc5c78f20B168Fd1",
                        "12f6b90d66bda29807cf9ff14b2e537c25080154fc4fafed446306e8356ff425",
                        "e7c92e164b83e1b53e41e5d87d478bb07d7b19d105143e426e1ef08f7b37f224"),
                new Metadata(null, new BigInteger("186a20d9b00315855ff5622a083aca6b2d34ef66ef6e0a4de670f5b2fde37e0d", 16),
                        TypeOfUser.v1, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("should be able to login a v1 user")
    @Test
    public void shouldLoginForV1User() throws ExecutionException, InterruptedException, TorusException {
        String verifier = "google-lrc";
        String email = "himanshu@tor.us";
        String token = JwtUtils.generateIdToken(email, algorithmRs);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setNetwork(TorusNetwork.TESTNET.toString());
        opts.setAllowHost("https://signer.tor.us/api/allow");
        opts.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
        torusUtils = new TorusUtils(opts);
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.TESTNET);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(verifier, email).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", email);
        }}, token).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xbeFfcC367D741C53A63F50eA805c1e93d3C64fEc",
                        "2b1c47c8fbca61ee7f82a8aff53a357f6b66af0dffbef6a3e3ac649180616e51",
                        "fef450a5263f7c57605dd439225faee830943cb484e8dfe1f3c82c3d538f61af",
                        "dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9"),
                new OAuthKeyData("0xbeFfcC367D741C53A63F50eA805c1e93d3C64fEc",
                        "19499419649390845580457764508395315278888806091504683223990787274846316359249",
                        "115319130816082515337172443545355478994523337895659677857630000207487199830447",
                        "dca7f29d234dc71561efe1a874d872bf34f6528bc042fe35e57197eac1f14eb9"),
                new SessionData(new ArrayList<>(), ""),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }


    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        VerifierArgs args = new VerifierArgs(TORUS_TEST_VERIFIER, email, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getEvmAddress(), "");
    }

    @DisplayName("should keep public address same")
    @Test
    public void shouldKeyPublicAddressSame() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        VerifierArgs args = new VerifierArgs(TORUS_TEST_VERIFIER, email, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey result1 = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        TorusPublicKey result2 = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertThat(result1.getFinalKeyData()).isEqualToComparingFieldByFieldRecursively(result2.getFinalKeyData());
        assertThat(result1.getoAuthKeyData()).isEqualToComparingFieldByFieldRecursively(result2.getoAuthKeyData());
        assertThat(result1.getMetadata()).isEqualToComparingFieldByFieldRecursively(result2.getMetadata());
    }

    @DisplayName("Login test")
    @Test
    public void shouldLogin() throws ExecutionException, InterruptedException {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs), new ImportedShare[]{}).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("3c590f140b24051855f945c06629d0b66262675055b4d8a92da7d2ec4d92b08a"));
    }

    @DisplayName("Should be able to login even when node is down")
    @Test
    public void shouldLoginWhenNodeIsDown() throws Exception {
        String token = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        torusNodeEndpoints[1] = "https://example.com";
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(torusNodeEndpoints, nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, token, new ImportedShare[]{}).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("3c590f140b24051855f945c06629d0b66262675055b4d8a92da7d2ec4d92b08a"));
    }

    @DisplayName("should fetch public address when verifierID hash enabled")
    @Test
    public void shouldFetchPubAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "extendedVerifierId");
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
                        "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
                        "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0"),
                new FinalPubKeyData("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
                        "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
                        "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e"),
                new Metadata(new GetOrSetNonceResult.PubNonce("d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
                        "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e"),
                        new BigInteger("51eb06f7901d5a8562274d3e53437328ca41ad96926f075122f6bd50e31be52d", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Should fetch user type and public address when verifierID hash enabled")
    @Test
    public void testFetchUserTypeAndPublicAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, nodeDetails.getTorusNodePub(), args).get();
        assertEquals("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03", torusPublicKey.getFinalKeyData().getEvmAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
                        "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
                        "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0"),
                new FinalPubKeyData("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
                        "21cd0ae3168d60402edb8bd65c58ff4b3e0217127d5bb5214f03f84a76f24d8a",
                        "575b7a4d0ef9921b3b1b84f30d412e87bc69b4eab83f6706e247cceb9e985a1e"),
                new Metadata(new GetOrSetNonceResult.PubNonce("d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
                        "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e"),
                        new BigInteger("51eb06f7901d5a8562274d3e53437328ca41ad96926f075122f6bd50e31be52d", 16), TypeOfUser.v2, false),
                new NodesData(new ArrayList<>())
        ));
    }

    @DisplayName("Aggregate Login test")
    @Test
    public void shouldAggregateLogin() throws ExecutionException, InterruptedException, TorusException {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).substring(2);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_AGGREGATE_VERIFIER, new HashMap<String, Object>() {{
            put("verify_params", new VerifyParams[]{new VerifyParams(idToken, TORUS_TEST_EMAIL)});
            put("sub_verifier_ids", new String[]{TORUS_TEST_VERIFIER});
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, hashedIdToken).get();
        assertNotNull(retrieveSharesResponse.getFinalKeyData().getEvmAddress());
        assertNotEquals(retrieveSharesResponse.getFinalKeyData().getEvmAddress(), "");
    }

    // TODO Check below test case is failing
    @DisplayName("Should fetch pub address of tss verifier id")
    @Test
    public void shouldFetchPubAddressOfTSSVerifierId() throws Exception {
        String email = TORUS_EXTENDED_VERIFIER_EMAIL;
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        VerifierArgs verifierArgs = new VerifierArgs(TORUS_TEST_VERIFIER, email, tssVerifierId);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusNodePub(), verifierArgs).get();
        assertEquals("0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30", torusPublicKey.getFinalKeyData().getEvmAddress());
        TorusPublicKey torusPublicKey1 = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), null, verifierArgs).get();
        assertEquals(torusPublicKey1.getFinalKeyData().getEvmAddress(), torusPublicKey.getFinalKeyData().getEvmAddress());
    }

    @DisplayName("should allow test tss verifier id to fetch shares")
    @Test
    public void shouldAllowTESTTSSVerifierIdToFetchShares() throws ExecutionException, InterruptedException, TorusException {
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
        assertEquals(new BigInteger("0"), result.metadata.nonce);
        assertEquals(result.metadata.upgraded, true);
    }

    @DisplayName("should be able to login when verifierID hash enabled")
    @Test
    public void testShouldBeAbleToLoginWhenVerifierIdHashEnabled() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        VerifierArgs args = new VerifierArgs(HashEnabledVerifier, TORUS_TEST_EMAIL, "");
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), nodeDetails.getTorusIndexes(), HashEnabledVerifier, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, idToken).get();
        assert (retrieveSharesResponse.getFinalKeyData().getPrivKey().equals("066270dfa345d3d0415c8223e045f366b238b50870de7e9658e3c6608a7e2d32"));
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xF79b5ffA48463eba839ee9C97D61c6063a96DA03",
                        "15288602791273750074006916629209422708636155719321341944582659737320049233290",
                        "39512845000186250107791179215691362545116071539007469639341362275861040486942",
                        "066270dfa345d3d0415c8223e045f366b238b50870de7e9658e3c6608a7e2d32"),
                new OAuthKeyData("0x4135ad20D2E9ACF37D64E7A6bD8AC34170d51219",
                        "9c591943683c0e5675f99626cea84153a3c5b72c6e7840f8b8b53d0f2bb50c67",
                        "9d9896d82e565a2d5d437745af6e4560f3564c2ac0d0edcb72e0b508b3ac05a0",
                        "b47769e81328794adf3534e58d02803ca2a5e4588db81780f5bf679c77988946"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce("d6404befc44e3ab77a8387829d77e9c77a9c2fb37ae314c3a59bdc108d70349d",
                        "1054dfe297f1d977ccc436109cbcce64e95b27f93efc0f1dab739c9146eda2e"),
                        new BigInteger("51eb06f7901d5a8562274d3e53437328ca41ad96926f075122f6bd50e31be52d", 16), TypeOfUser.v2,
                        false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("should be able to import a key for a new user")
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

    @Test
    public void generateIdToken() throws Exception {
        String email = "cuspedrafael@hotmail.co.uk";
        String idToken = JwtUtils.generateIdToken(email, algorithmRs);
        System.out.println("idToken" + idToken);
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
    }

}
