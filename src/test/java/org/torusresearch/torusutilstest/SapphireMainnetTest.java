package org.torusresearch.torusutilstest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Header;

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
import org.torusresearch.torusutils.types.common.SessionToken;
import org.torusresearch.torusutils.types.common.TorusKey;
import org.torusresearch.torusutils.types.common.TorusOptions;
import org.torusresearch.torusutils.types.common.TorusPublicKey;
import org.torusresearch.torusutils.types.common.TypeOfUser;
import org.torusresearch.torusutilstest.utils.JwtUtils;
import org.torusresearch.torusutilstest.utils.PemUtils;
import org.web3j.crypto.Hash;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class SapphireMainnetTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-aggregate-sapphire-mainnet";

    static String TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com";
    static String HashEnabledVerifier = "torus-test-verifierid-hash";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeEach
    void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, TorusUtilError {
        fetchNodeDetails = new FetchNodeDetails(Web3AuthNetwork.SAPPHIRE_MAINNET);
        TorusOptions opts = new TorusOptions("YOUR_CLIENT_ID", Web3AuthNetwork.SAPPHIRE_MAINNET, null, 0, true);
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws Exception {
        String verifier = "tkey-google-sapphire-mainnet";
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(verifier, TORUS_TEST_EMAIL).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), verifier, TORUS_TEST_EMAIL, null);
        assertEquals("0x327b2742768B436d09153429E762FADB54413Ded", torusPublicKey.getFinalKeyData().getWalletAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xb1a49C6E50a1fC961259a8c388EAf5953FA5152b",
                        "a9f5a463aefb16e90f4cbb9de4a5b6b7f6c6a3831cefa0f20cccb9e7c7b01c20",
                        "3376c6734da57ab3a67c7792eeea20707d16992dd2c827a59499f4c056b00d08"),
                new FinalPubKeyData("0x327b2742768B436d09153429E762FADB54413Ded",
                        "1567e030ca76e520c180c50bc6baed07554ebc35c3132495451173e9310d8be5",
                        "123c0560757ffe6498bf2344165d0f295ea74eb8884683675e5f17ae7bb41cdb"),
                new Metadata(new PubNonce("56e803db7710adbfe0ecca35bc6a3ad27e966df142e157e76e492773c88e8433",
                        "f4168594c1126ca731756dd480f992ee73b0834ba4b787dd892a9211165f50a3"),
                        new BigInteger("0", 16), TypeOfUser.v2, false, torusPublicKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws Exception {
        String verifier = "tkey-google-sapphire-mainnet";
        String verifierId = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(verifier, verifierId).get();
        TorusPublicKey result = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), verifier, verifierId, null);
        assertNotEquals("", result.getFinalKeyData().getWalletAddress());
        assertNotNull(result.getFinalKeyData().getWalletAddress());
        assertNotEquals("", result.getFinalKeyData().getWalletAddress());
        assertNotNull(result.getFinalKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, result.getMetadata().getTypeOfUser());
        assertFalse(result.getMetadata().isUpgraded());
    }

    @DisplayName("should fetch pubic address of tssVerifierId")
    @Test
    public void shouldFetchPubicAddressOfTssVerifierId() throws Exception {
        String email = TORUS_EXTENDED_VERIFIER_EMAIL;
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), TORUS_TEST_VERIFIER, email, tssVerifierId);
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x98EC5b049c5C0Dc818C69e95CF43534AEB80261A",
                        "a772c71ca6c650506f26a180456a6bdf462996781a10f1740f4e65314f360f29",
                        "776c2178ff4620c67197b2f26b1222503919ff26a7cbd0fdbc91a2c9764e56cb"),
                new FinalPubKeyData("0x98EC5b049c5C0Dc818C69e95CF43534AEB80261A",
                        "a772c71ca6c650506f26a180456a6bdf462996781a10f1740f4e65314f360f29",
                        "776c2178ff4620c67197b2f26b1222503919ff26a7cbd0fdbc91a2c9764e56cb"),
                new Metadata(torusPublicKey.getMetadata().getPubNonce(),
                        new BigInteger("0"), TypeOfUser.v2, false, torusPublicKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should assign key to tss verifier id")
    @Test
    public void shouldAssignKeyToTssVerifierId() throws Exception {
        String email = JwtUtils.getRandomEmail();
        int nonce = 0;
        String tssTag = "default";
        String tssVerifierId = email + "\u0015" + tssTag + "\u0016" + nonce;
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        TorusPublicKey result = torusUtils.getPublicAddress(nodeDetails.getTorusNodeSSSEndpoints(), TORUS_TEST_VERIFIER, email, tssVerifierId);
        assertNotNull(result.getFinalKeyData().getWalletAddress());
        assertNotNull(result.getoAuthKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, result.getMetadata().getTypeOfUser());
        assertFalse(result.getMetadata().isUpgraded());
    }

    @DisplayName("should fetch public address when verifierID hash enabled")
    @Test
    public void shouldFetchPubAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, HashEnabledVerifier, TORUS_TEST_EMAIL, null);
        assertTrue(torusPublicKey.getMetadata().getServerTimeOffset() < 20);
        assertEquals("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB", torusPublicKey.getFinalKeyData().getWalletAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c"),
                new FinalPubKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90"),
                new Metadata(new PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("0", 16), TypeOfUser.v2, false, torusPublicKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should fetch user type and public address when verifierID hash enabled")
    @Test
    public void shouldFetchUserTypeAndPubAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, HashEnabledVerifier, TORUS_TEST_EMAIL, null);
        assertTrue(torusPublicKey.getMetadata().getServerTimeOffset() < 20);
        assertEquals("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB", torusPublicKey.getFinalKeyData().getWalletAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c"),
                new FinalPubKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90"),
                new Metadata(new PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("0", 16), TypeOfUser.v2, false,
                        torusPublicKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should be able to login when verifierID hash enabled")
    @Test
    public void testShouldBeAbleToLoginWhenVerifierIdHashEnabled() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, null, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        TorusKey torusKey = torusUtils.retrieveShares(nodeDetails.getTorusNodeSSSEndpoints(), HashEnabledVerifier,
                verifierParams, idToken, null);
        assertTrue(torusKey.getMetadata().getServerTimeOffset() < 20);
        assert ((torusKey.getFinalKeyData().getPrivKey() != null) && torusKey.getFinalKeyData().getPrivKey().equals("13941ecd812b08d8a33a20bc975f0cd1c3f82de25b20c0c863ba5f21580b65f6"));
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90",
                        "13941ecd812b08d8a33a20bc975f0cd1c3f82de25b20c0c863ba5f21580b65f6"),
                new OAuthKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c",
                        "d768b327cbde681e5850a7d14f1c724bba2b8f8ab7fe2b1c4f1ee6979fc25478"),
                new SessionData(torusKey.getSessionData().getSessionTokenData(), torusKey.getSessionData().getSessionAuthKey()),
                new Metadata(new PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("3c2b6ba5b54ca0ba4ae978eb48429a84c47b7b3e526b35e7d46dd716887f52bf", 16), TypeOfUser.v2,
                        false, torusKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should be able to login")
    @Test
    public void shouldBeAbleToLogin() throws Exception {
        String token = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, null, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        TorusKey torusKey = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), TORUS_TEST_VERIFIER,
                verifierParams, token, null);
        assert ((torusKey.getFinalKeyData().getPrivKey() != null) && torusKey.getFinalKeyData().getPrivKey().equals("dfb39b84e0c64b8c44605151bf8670ae6eda232056265434729b6a8a50fa3419"));
        assertThat(torusKey).isEqualToComparingFieldByFieldRecursively(new TorusKey(
                new FinalKeyData("0x70520A7F04868ACad901683699Fa32765C9F6871",
                        "adff099b5d3b1e238b43fba1643cfa486e8d9e8de22c1e6731d06a5303f9025b",
                        "21060328e7889afd303acb63201b6493e3061057d1d81279931ab4a6cabf94d4",
                        "dfb39b84e0c64b8c44605151bf8670ae6eda232056265434729b6a8a50fa3419"),
                new OAuthKeyData("0x925c97404F1aBdf4A8085B93edC7B9F0CEB3C673",
                        "5cd8625fc01c7f7863a58c914a8c43b2833b3d0d5059350bab4acf6f4766a33d",
                        "198a4989615c5c2c7fa4d49c076ea7765743d09816bb998acb9ff54f5db4a391",
                        "90a219ac78273e82e36eaa57c15f9070195e436644319d6b9aea422bb4d31906"),
                new SessionData(torusKey.getSessionData().getSessionTokenData(), torusKey.getSessionData().getSessionAuthKey()),
                new Metadata(new PubNonce("ab4d287c263ab1bb83c37646d0279764e50fe4b0c34de4da113657866ddcf318",
                        "ad35db2679dfad4b62d77cf753d7b98f73c902e5d101cc2c3c1209ece6d94382"),
                        new BigInteger("4f1181d8689f0d0960f1a6f9fe26e03e557bdfba11f4b6c8d7b1285e9c271b13", 16),
                        TypeOfUser.v2, false, torusKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should be able to aggregate login")
    @Test
    public void shouldAggregateLogin() throws Exception {
        String email = JwtUtils.getRandomEmail();
        String idToken = JwtUtils.generateIdToken(email, algorithmRs);
        String hashedIdToken = Hash.sha3String(idToken).replace("0x","");


        VerifierParams verifierParams = new VerifierParams(email, null, new String[]{TORUS_TEST_VERIFIER}, new VerifyParams[]{new VerifyParams(email, idToken)});
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_AGGREGATE_VERIFIER, email).get();
        String[] endpoints = nodeDetails.getTorusNodeSSSEndpoints();
        TorusKey result = torusUtils.retrieveShares(endpoints, TORUS_TEST_AGGREGATE_VERIFIER,
                verifierParams, hashedIdToken, null);
        assertNotNull(result.getFinalKeyData().getWalletAddress());
        assertNotNull(result.getoAuthKeyData().getWalletAddress());
        assertEquals(TypeOfUser.v2, result.getMetadata().getTypeOfUser());
        assertNotNull(result.getMetadata().getNonce());
    }

    @DisplayName("Should fetch user type and public address when verifierID hash enabled")
    @Test
    public void testFetchUserTypeAndPublicAddressWhenVerfierIdHasEnabled() throws Exception {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(HashEnabledVerifier, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeSSSEndpoints();
        TorusPublicKey torusPublicKey = torusUtils.getPublicAddress(torusNodeEndpoints, HashEnabledVerifier, TORUS_TEST_EMAIL, null);
        assertEquals("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB", torusPublicKey.getFinalKeyData().getWalletAddress());
        assertThat(torusPublicKey).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC",
                        "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8",
                        "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c"),
                new FinalPubKeyData("0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB",
                        "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8",
                        "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90"),
                new Metadata(new PubNonce("498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd",
                        "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f"),
                        new BigInteger("0", 16), TypeOfUser.v2, false, torusPublicKey.getMetadata().getServerTimeOffset()),
                new NodesData(torusPublicKey.getNodesData().getNodeIndexes())
        ));
    }

    @DisplayName("should be able to update the `sessionTime` of the token signature data")
    @Test
    public void shouldUpdateSessionTimeOfTokenSignatureData() throws Exception {
        String idToken = JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs);
        VerifierParams verifierParams = new VerifierParams(TORUS_TEST_EMAIL, null, null, null);
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        String[] torusNodeEndpoints = nodeDetails.getTorusNodeEndpoints();

        int customSessionTime = 3600;
        torusUtils.setSessionTime(customSessionTime);
        TorusKey torusKey = torusUtils.retrieveShares(torusNodeEndpoints, TORUS_TEST_VERIFIER,
                verifierParams, idToken, null);

        for (SessionToken sessionToken : torusKey.getSessionData().getSessionTokenData()) {
            String decodedToken = new String(Base64.getDecoder().decode(sessionToken.getToken()), StandardCharsets.UTF_8);
            Header jwt = JwtUtils.parseTokenHeader(decodedToken);
            Date expiry = jwt.getHeaderClaim("exp").asDate();
            Date now = new Date();
            long diffInMillis = Math.abs(expiry.getTime() - now.getTime());
            long diff = TimeUnit.SECONDS.convert(diffInMillis, TimeUnit.MILLISECONDS);
            assert (diff > (customSessionTime - 30));
            assert (customSessionTime <= diff);
        }
    }
}
