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
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

public class OneKeyTest {

    static FetchNodeDetails fetchNodeDetails;

    static TorusUtils torusUtils;
    static Algorithm algorithmRs;

    static String TORUS_TEST_VERIFIER = "torus-test-health";
    static String TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate";

    static String TORUS_TEST_EMAIL = "hello@tor.us";

    @BeforeAll
    static void setup() throws ExecutionException, InterruptedException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Setup Starting");
        fetchNodeDetails = new FetchNodeDetails(TorusNetwork.TESTNET);
        TorusCtorOptions opts = new TorusCtorOptions("Custom");
        opts.setEnableOneKey(true);
        opts.setNetwork(TorusNetwork.TESTNET.toString());
        opts.setClientId("BG4pe3aBso5SjVbpotFQGnXVHgxhgOxnqnNBKyjfEJ3izFvIVWUaMIzoCrAfYag8O6t6a6AOvdLcS4JR2sQMjR4");
        torusUtils = new TorusUtils(opts);
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile("src/test/java/org/torusresearch/torusutilstest/keys/key.pem", "EC");
        ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(privateKey.getParams().getGenerator(), privateKey.getParams()));
        algorithmRs = Algorithm.ECDSA256(publicKey, privateKey);
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("google-lrc", TORUS_TEST_EMAIL, "");
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(args.getVerifier(), args.getVerifierId()).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        assertEquals(TypeOfUser.v1, publicAddress.getMetadata().getTypeOfUser());
        assertEquals("0x5b56E06009528Bffb1d6336575731ee3B63f6150", publicAddress.getFinalKeyData().getEvmAddress());
        assertThat(publicAddress).isEqualToComparingFieldByFieldRecursively(new TorusPublicKey(
                new OAuthPubKeyData("0x5b56E06009528Bffb1d6336575731ee3B63f6150",
                        "38a259ba42875243bba7254dd75eb3b448d83f03726ca1359fd0262faa8cede7",
                        "3ad7aece972e471eed7002149e830c0f5b60be93ad91bb7313437bd0702b3d79"),
                new FinalPubKeyData("0x5b56E06009528Bffb1d6336575731ee3B63f6150",
                        "38a259ba42875243bba7254dd75eb3b448d83f03726ca1359fd0262faa8cede7",
                        "3ad7aece972e471eed7002149e830c0f5b60be93ad91bb7313437bd0702b3d79"),
                new Metadata(null, BigInteger.ZERO, TypeOfUser.v1, false),
                new NodesData(publicAddress.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("Key Assign test")
    @Test
    public void shouldKeyAssign() throws ExecutionException, InterruptedException {
        String email = JwtUtils.getRandomEmail();
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        TorusPublicKey publicAddress = torusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), new VerifierArgs(TORUS_TEST_VERIFIER, email, ""), true).get();
        System.out.println(email + " -> " + publicAddress.getFinalKeyData().getEvmAddress());
        assertNotNull(publicAddress.getFinalKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getFinalKeyData().getEvmAddress(), "");
        assertNotNull(publicAddress.getoAuthKeyData().getEvmAddress());
        assertNotEquals(publicAddress.getoAuthKeyData().getEvmAddress(), "");
        assertEquals(publicAddress.getMetadata().getTypeOfUser(), TypeOfUser.v2);
        assertEquals(publicAddress.getMetadata().isUpgraded(), false);
    }

    @DisplayName("Login test v1")
    @Test
    public void shouldLoginV1() throws ExecutionException, InterruptedException, TorusException {
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, TORUS_TEST_EMAIL).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", TORUS_TEST_EMAIL);
        }}, JwtUtils.generateIdToken(TORUS_TEST_EMAIL, algorithmRs)).get();
        assertEquals("296045a5599afefda7afbdd1bf236358baff580a0fe2db62ae5c1bbe817fbae4", retrieveSharesResponse.getFinalKeyData().getPrivKey());
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x53010055542cCc0f2b6715a5c53838eC4aC96EF7",
                        "28791725684617741539794713367138009203742373976762713376477976695969223421073",
                        "31963659117858991836451415875221007566688067606268800158620363382690552926420",
                        "296045a5599afefda7afbdd1bf236358baff580a0fe2db62ae5c1bbe817fbae4"),
                new OAuthKeyData("0xEfd7eDAebD0D99D1B7C8424b54835457dD005Dc4",
                        "18409385c38e9729eb6b7837dc8f234256233ffab1ed7eeb1c23b230333396b4",
                        "17d35ffc722d7a8dd88353815e9553cacf567c5f3b8d082adac9d653367ce47a",
                        "68ee4f97468ef1ae95d18554458d372e31968190ae38e377be59d8b3c9f7a25"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce(
                        "8e8c399d8ba00ff88e6c42eb40c10661f822868ba2ad8fe12a8830e996b1e25d",
                        "554b12253694bf9eb98485441bba7ba220b78cb78ee21664e96f934d10b1494d"
                ), new BigInteger("22d160abe5320fe2be52a57c7aca8fe5d7e5eff104ff4d2b32767e3344e040bf", 16), TypeOfUser.v2, false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }

    @DisplayName("Login test v2")
    @Test
    public void shouldLoginV2() throws ExecutionException, InterruptedException, TorusException {
        String email = "Jonathan.Nolan@hotmail.com";
        NodeDetails nodeDetails = fetchNodeDetails.getNodeDetails(TORUS_TEST_VERIFIER, email).get();
        RetrieveSharesResponse retrieveSharesResponse = torusUtils.retrieveShares(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusIndexes(), TORUS_TEST_VERIFIER, new HashMap<String, Object>() {{
            put("verifier_id", email);
        }}, JwtUtils.generateIdToken(email, algorithmRs)).get();
        System.out.println(retrieveSharesResponse.getFinalKeyData().getPrivKey() + " priv key " + retrieveSharesResponse.getFinalKeyData().getEvmAddress() + " nonce " + retrieveSharesResponse.getMetadata().getNonce());
        assertEquals(retrieveSharesResponse.getFinalKeyData().getPrivKey(), "9ec5b0504e252e35218c7ce1e4660eac190a1505abfbec7102946f92ed750075");
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0x2876820fd9536BD5dd874189A85d71eE8bDf64c2",
                        "78384639273521458089047405072137536963800483460438205915578317497287406022228",
                        "57974546825806475821443120888451716098460024516231724925952591729816755206881",
                        "9ec5b0504e252e35218c7ce1e4660eac190a1505abfbec7102946f92ed750075"),
                new OAuthKeyData("0x54de3Df0CA76AAe3e171FB410F0626Ab759f3c24",
                        "49d69b8550bb0eba77595c73bf57f0463ff96adf6b50d44f9e1bcf2b3fb7976e",
                        "d63bac65bdfc7484a28d4362347bbd098095db190c14a4ce9dbaafe74803eccc",
                        "f4b7e0fb1e6f6fbac539c55e22aff2900947de652d2d6254a9cd8709f505f83a"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce(
                        "f494a5bf06a2f0550aafb6aabeb495bd6ea3ef92eaa736819b5b0ad6bfbf1aab",
                        "35df3d3a14f88cbba0cfd092a1e5a0e4e725ba52a8d45719614555542d701f18"
                ), new BigInteger("aa0dcf552fb5be7a5c52b783c1b61c1aca7113872e172a5818994715c8a5497c", 16), TypeOfUser.v2, false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
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
        assertEquals("0xE1155dB406dAD89DdeE9FB9EfC29C8EedC2A0C8B", retrieveSharesResponse.getFinalKeyData().getEvmAddress());
        assertThat(retrieveSharesResponse).isEqualToComparingFieldByFieldRecursively(new RetrieveSharesResponse(
                new FinalKeyData("0xE1155dB406dAD89DdeE9FB9EfC29C8EedC2A0C8B",
                        "54456953762754495648745105516045030283478616462159514856919303547649756337955",
                        "20962321879729253335080221216649438668436420171192718569043641743378689094907",
                        "ad47959db4cb2e63e641bac285df1b944f54d1a1cecdaeea40042b60d53c35d2"),
                new OAuthKeyData("0x5a165d2Ed4976BD104caDE1b2948a93B72FA91D2",
                        "aba2b085ae6390b3eb26802c3239bb7e3b9ed8ea6e1dcc28aeb67432571f20fc",
                        "f1a2163cba5620b7b40241a6112e7918e9445b0b9cfbbb9d77b2de6f61ed5c27",
                        "d9733fc1098151f3e3289673e7c69c4ed46cbbdbc13416560e14741524d2d51a"),
                new SessionData(retrieveSharesResponse.sessionData.getSessionTokenData(), retrieveSharesResponse.sessionData.getSessionAuthKey()),
                new Metadata(new GetOrSetNonceResult.PubNonce(
                        "376c0ac5e15686633061cf5833dd040365f91377686d7ab5338c5202bd963a2f",
                        "794d7edb6a5ec0307dd40789274b377f37f293b0410a6cbd303db309536099b7"
                ), new BigInteger("d3d455dcab49dc700319244e9e187f443596f2acbce238cff1c215d8809fa1f9", 16), TypeOfUser.v2, false),
                new NodesData(retrieveSharesResponse.nodesData.nodeIndexes)
        ));
    }
}
