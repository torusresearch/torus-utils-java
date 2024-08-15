package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.helpers.Utils.addLeading0sForLength64;
import static org.torusresearch.torusutils.helpers.Utils.padLeft;

import com.google.gson.Gson;

import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.requests.NonceMetadataParams;
import org.torusresearch.torusutils.apis.requests.SetNonceData;
import org.torusresearch.torusutils.helpers.encryption.Encryption;
import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.Polynomial;
import org.torusresearch.torusutils.types.Share;
import org.torusresearch.torusutils.types.common.ImportedShare;
import org.torusresearch.torusutils.types.common.PrivateKeyData;
import org.torusresearch.torusutils.types.common.TorusKeyType;
import org.torusresearch.torusutils.types.common.ecies.Ecies;
import org.torusresearch.torusutils.types.common.ecies.EciesHexOmitCipherText;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class KeyUtils {
    static final protected Provider provider  = new BouncyCastleProvider();
    static final protected ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");


    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", provider);
        kpgen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        return kpgen.generateKeyPair();
    }

    public static byte [] serializePublicKey (@NotNull PublicKey key, @NotNull Boolean compressed) {
        org.bouncycastle.jce.interfaces.ECPublicKey eckey = (ECPublicKey)key;
        return eckey.getQ().getEncoded(compressed);
    }

    public static PublicKey deserializePublicKey (@NotNull byte [] data) throws Exception
    {
        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", provider);
        return kf.generatePublic(pubKey);
    }

    public static byte [] serializePrivateKey (@NotNull PrivateKey key) {
        ECPrivateKey eckey = (ECPrivateKey)key;
        return eckey.getD().toByteArray();
    }
    public static PrivateKey deserializePrivateKey (@NotNull byte [] data) throws Exception {
        ECPrivateKeySpec prvkey = new org.bouncycastle.jce.spec.ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", provider);
        return kf.generatePrivate(prvkey);
    }

    public static byte[] randomNonce() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        return KeyUtils.serializePrivateKey(keyPair.getPrivate());
    }

    public static BigInteger getOrderOfCurve() {
        return params.getN();
    }

    public static String privateToPublic(@NotNull BigInteger key) {
        return  "04" + ECKeyPair.create(key).getPublicKey().toString(16);
    }

    public static String generateAddressFromPrivKey(@NotNull String privateKey) throws Exception {
        PrivateKey privKey = deserializePrivateKey(Hex.decode(privateKey));
        return Keys.toChecksumAddress(Keys.getAddress(ECKeyPair.create(privKey.getEncoded())));
    }

    public static String generateAddressFromPubKey(@NotNull String publicKeyX, @NotNull String publicKeyY) {
        String finalPublicKey = publicKeyX + publicKeyY;
        return Keys.toChecksumAddress(Keys.getAddress(finalPublicKey));
    }

    public static String[] getPublicKeyCoords(@NotNull String pubKey) throws TorusUtilError {
        String publicKeyUnprefixed = pubKey;
        if (publicKeyUnprefixed.length() > 128) {
            publicKeyUnprefixed = Utils.strip04Prefix(publicKeyUnprefixed);
        }

        if (publicKeyUnprefixed.length() <= 128) {
            Utils.padLeft(publicKeyUnprefixed, '0', 128);
        } else {
            throw new TorusUtilError("Invalid public key size");
        }

        String xCoord = publicKeyUnprefixed.substring(0, 64);
        String yCoord = publicKeyUnprefixed.substring(64);

        return new String[]{xCoord, yCoord};
    }

    public static String getPublicKeyFromCoords(@NotNull String pubKeyX, @NotNull String pubKeyY, boolean prefixed) {
        String X = addLeading0sForLength64(pubKeyX);
        String Y = addLeading0sForLength64(pubKeyY);

        return prefixed ? "04" + X + Y : X + Y;
    }

    public static String combinePublicKeysFromStrings(@NotNull List<String> keys, boolean compressed) throws TorusUtilError {
        List<ECPoint> collection = new ArrayList<>();

        for (String item : keys) {
            ECPoint point = CustomNamedCurves.getByName("secp256k1").getCurve().decodePoint(Hex.decode(item));
            collection.add(point);
        }

        return combinePublicKeys(collection, compressed);
    }

    public static String combinePublicKeys(@NotNull List<? extends ECPoint> keys, boolean compressed) throws TorusUtilError {
        if (keys.isEmpty()) {
            throw new TorusUtilError("The keys list cannot be empty");
        }

        ECPoint combinedPoint = keys.get(0);
        for (int i = 1; i < keys.size(); i++) {
            combinedPoint = combinedPoint.add(keys.get(i));
        }

        byte[] serializedPoint = compressed ? combinedPoint.getEncoded(true) : combinedPoint.getEncoded(false);
        return Hex.toHexString(serializedPoint);
    }

    public static PrivateKeyData generateKeyData(@NotNull String privateKey) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        BigInteger scalar = new BigInteger(Hex.decode(privateKey));
        BigInteger randomNonce = new BigInteger(randomNonce());

        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
        BigInteger oAuthKey = scalar.subtract(randomNonce).mod(params.getN());

        ECPrivateKeyParameters oAuthPrivKey = new ECPrivateKeyParameters(oAuthKey, domainParams);
        ECPoint oAuthPubPoint = domainParams.getG().multiply(oAuthPrivKey.getD());
        ECPublicKeyParameters oAuthPubKey = new ECPublicKeyParameters(oAuthPubPoint, domainParams);

        ECPrivateKeyParameters finalPrivKey = new ECPrivateKeyParameters(scalar, domainParams);
        ECPoint finalPubPoint = domainParams.getG().multiply(finalPrivKey.getD());
        ECPublicKeyParameters finalPubKey = new ECPublicKeyParameters(finalPubPoint, domainParams);

        return new PrivateKeyData(
                padLeft(oAuthKey.toString(16), '0', 64),
                Hex.toHexString(oAuthPubKey.getQ().getEncoded(false)),
                padLeft(randomNonce.toString(16), '0', 64),
                padLeft(oAuthKey.toString(16), '0', 64),
                Hex.toHexString(oAuthPubKey.getQ().getEncoded(false)),
                padLeft(privateKey, '0', 64),
                Hex.toHexString(finalPubKey.getQ().getEncoded(false))
        );
    }

    public static NonceMetadataParams generateNonceMetadataParams(@NotNull String operation, @NotNull BigInteger privateKey, @NotNull BigInteger nonce, @NotNull Integer serverTimeOffset) {
        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
        ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(privateKey, domainParams);
        ECPoint oAuthPubPoint = domainParams.getG().multiply(privKeyParams.getD());
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(oAuthPubPoint, domainParams);

        BigInteger timeSeconds = BigInteger.valueOf(System.currentTimeMillis() / 1000L);
        BigInteger timestamp = timeSeconds.add(BigInteger.valueOf(serverTimeOffset));

        // Serialize public key into padded X and Y coordinates
        String derivedPubKeyString = Hex.toHexString(publicKeyParams.getQ().getEncoded(false));
        String derivedPubKeyX = derivedPubKeyString.substring(2, 66);
        String derivedPubKeyY = derivedPubKeyString.substring(66);

        // Create SetNonceData object with operation and timestamp
        SetNonceData setNonceData = new SetNonceData(operation, timestamp.toString(16), null, Utils.padLeft(nonce.toString(16), '0', 64));

        // Convert SetNonceData object to JSON string
        Gson gson = new Gson();
        String encodedData = gson.toJson(setNonceData);

        // Hash the JSON string using keccak256 (SHA-3)
        byte[] hashedData = Hash.sha3(encodedData.getBytes(StandardCharsets.UTF_8));

        // Sign the hashed data using ECDSA with the private key
        SecureRandom random = new SecureRandom();
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, new ParametersWithRandom(privKeyParams, random));
        BigInteger[] signature = signer.generateSignature(hashedData);

        // Format the signature into a padded hexadecimal string
        String sig = Utils.padLeft(signature[0].toString(16), '0', 64) +
                Utils.padLeft(signature[1].toString(16), '0', 64) +
                Utils.padLeft("", '0', 2); // Assuming padding to ensure consistent length

        // Convert the hexadecimal signature string to bytes
        byte[] sigBytes = Hex.decode(sig);

        // Encode the signature bytes to Base64
        String finalSig = new String(Base64.getEncoder().encode(sigBytes), StandardCharsets.UTF_8);

        // Return a new NonceMetadataParams object with the derived values
        return new NonceMetadataParams(derivedPubKeyX, derivedPubKeyY, setNonceData,
                Base64.getEncoder().encodeToString(encodedData.getBytes(StandardCharsets.UTF_8)), finalSig, null, null, null);
    }

    public static List<ImportedShare> generateShares(@NotNull TorusKeyType keyType, @NotNull Integer serverTimeOffset, @NotNull List<BigInteger> nodeIndexes, @NotNull List<TorusNodePub> nodePubKeys, @NotNull String privateKey) throws Exception {
        if (keyType != TorusKeyType.secp256k1) {
            throw new RuntimeException("Unsupported key type");
        }

        PrivateKeyData keyData = generateKeyData(privateKey);

        int threshold = (nodePubKeys.size() / 2) + 1;
        int degree = threshold - 1;
        List<BigInteger> nodeIndexesBN = new ArrayList<>();
        for (BigInteger index : nodeIndexes) {
            nodeIndexesBN.add(new BigInteger(String.valueOf(index)));
        }

        Polynomial poly = Lagrange.generateRandomPolynomial(degree, new BigInteger(keyData.getOAuthKey(), 16), null);
        Map<String, Share> shares = poly.generateShares(nodeIndexesBN.toArray(new BigInteger[0]));

        NonceMetadataParams nonceParams = KeyUtils.generateNonceMetadataParams("getOrSetNonce", new BigInteger(keyData.getSigningKey(), 16), new BigInteger(keyData.getNonce(), 16), serverTimeOffset);

        List<Ecies> encShares = new ArrayList<>();
        for (int i = 0; i < nodePubKeys.size(); i++) {
            String indexHex = String.format("%064x", nodeIndexes.get(i));
            Share shareInfo = shares.get(indexHex);
            String nodePub = KeyUtils.getPublicKeyFromCoords(nodePubKeys.get(i).getX(), nodePubKeys.get(i).getY(), true);
            String share = Utils.padLeft(shareInfo.getShare().toString(16), '0', 64);
            Ecies encryptedMsg = Encryption.encrypt(Hex.decode(nodePub), share);
            encShares.add(encryptedMsg);
        }

        List<ImportedShare> sharesData = new ArrayList<>();
        for (int i = 0; i < nodePubKeys.size(); i++) {
            Ecies encrypted = encShares.get(i);
            String[] oAuthPub = getPublicKeyCoords(keyData.getOAuthPubKey());
            String[] signingPub = getPublicKeyCoords(keyData.getSigningPubKey());
            String[] finalPub = getPublicKeyCoords(keyData.getFinalPubKey());
            Point finalPoint = new Point(finalPub[0], finalPub[1]);

            ImportedShare importShare = new ImportedShare(
                    oAuthPub[0], oAuthPub[1], finalPoint,
                    signingPub[0], signingPub[1], encrypted.getCiphertext(),
                    new EciesHexOmitCipherText(encrypted.getIv(), encrypted.getEphemPublicKey(), encrypted.getMac(), "AES256"),
                    Integer.parseInt(nodeIndexes.get(i).toString(16), 16), keyType,
                    nonceParams.encodedData, nonceParams.signature);

            sharesData.add(importShare);
        }
        return sharesData;
    }
}

