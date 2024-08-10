package org.torusresearch.torusutils.helpers;

import static org.torusresearch.torusutils.helpers.Utils.addLeading0sForLength64;
import static org.torusresearch.torusutils.helpers.Utils.getRandomBytes;
import com.google.gson.Gson;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.torusresearch.fetchnodedetails.types.TorusNodePub;
import org.torusresearch.torusutils.apis.Ecies;
import org.torusresearch.torusutils.apis.EciesHexOmitCipherText;
import org.torusresearch.torusutils.helpers.Encryption.Encryption;
import org.torusresearch.torusutils.types.ImportedShare;
import org.torusresearch.torusutils.types.KeyType;
import org.torusresearch.torusutils.types.NonceMetadataParams;
import org.torusresearch.torusutils.types.Point;
import org.torusresearch.torusutils.types.Polynomial;
import org.torusresearch.torusutils.types.PrivateKeyData;
import org.torusresearch.torusutils.types.SetNonceData;
import org.torusresearch.torusutils.types.Share;
import org.web3j.crypto.ECDSASignature;
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
import java.util.List;
import java.util.Map;

public class KeyUtils {
    static final protected Provider provider  = new BouncyCastleProvider();
    static final protected X9ECParameters curveParams = ECNamedCurveTable.getByName("secp256k1");

    public static String keccak256(String input) {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] hash = keccak256(inputBytes);
        return Hex.toHexString(hash);
    }

    public static byte[] keccak256(byte[] input) {
        KeccakDigest digest = new KeccakDigest(256);
        digest.update(input, 0, input.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }


    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", provider);
        kpgen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        return kpgen.generateKeyPair();
    }

    public static byte [] serializePublicKey (PublicKey key, Boolean compressed) {
        org.bouncycastle.jce.interfaces.ECPublicKey eckey = (ECPublicKey)key;
        return eckey.getQ().getEncoded(compressed);
    }

    public static PublicKey deserializePublicKey (byte [] data) throws Exception
    {
        org.bouncycastle.jce.spec.ECParameterSpec params = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.jce.spec.ECPublicKeySpec pubKey = new org.bouncycastle.jce.spec.ECPublicKeySpec(
                params.getCurve().decodePoint(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", provider);
        return kf.generatePublic(pubKey);
    }

    public static byte [] serializePrivateKey (PrivateKey key) {
        ECPrivateKey eckey = (ECPrivateKey)key;
        return eckey.getD().toByteArray();
    }
    public static PrivateKey deserializePrivateKey (byte [] data) throws Exception {
        ECParameterSpec params = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.jce.spec.ECPrivateKeySpec prvkey = new org.bouncycastle.jce.spec.ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance("ECDH", provider);
        return kf.generatePrivate(prvkey);
    }

    public static String randomNonce() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        return Hex.toHexString(serializePrivateKey(keyPair.getPrivate()));
    }

    public static BigInteger getOrderOfCurve() {
        return curveParams.getN();
    }

    public static String generateAddressFromPrivKey(String privateKey) throws Exception {
        PrivateKey privKey = deserializePrivateKey(Hex.decode(privateKey));
        return Keys.toChecksumAddress(Keys.getAddress(ECKeyPair.create(privKey.getEncoded())));
    }

    public static String generateAddressFromPubKey(BigInteger pubKeyX, BigInteger pubKeyY) {
        ECNamedCurveParameterSpec curve = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint rawPoint = curve.getCurve().createPoint(pubKeyX, pubKeyY);
        String finalPubKey = Utils.padLeft(rawPoint.getAffineXCoord().toString(), '0', 64) + Utils.padLeft(rawPoint.getAffineYCoord().toString(), '0', 64);
        return Keys.toChecksumAddress(keccak256(finalPubKey).substring(64 - 38));
    }

    public static String[] getPublicKeyCoords(String pubKey) throws TorusUtilError {
        String publicKeyUnprefixed = pubKey;
        if (publicKeyUnprefixed.length() > 128) {
            publicKeyUnprefixed = Utils.strip04Prefix(publicKeyUnprefixed);
        }

        if (publicKeyUnprefixed.length() != 128) {
            throw new TorusUtilError("Invalid public key size");
        }

        String xCoord = publicKeyUnprefixed.substring(0, 64);
        String yCoord = publicKeyUnprefixed.substring(64);

        return new String[]{xCoord, yCoord};
    }

    public static String getPublicKeyFromCoords(String pubKeyX, String pubKeyY, boolean prefixed) {
        String X = addLeading0sForLength64(pubKeyX);
        String Y = addLeading0sForLength64(pubKeyY);

        return prefixed ? "04" + X + Y : X + Y;
    }

    public static String combinePublicKeysFromStrings(List<String> keys, boolean compressed) throws TorusUtilError {
        List<ECPoint> collection = new ArrayList<>();

        for (String item : keys) {
            ECPoint point = CustomNamedCurves.getByName("secp256k1").getCurve().decodePoint(Hex.decode(item));
            collection.add(point);
        }

        return combinePublicKeys(collection, compressed);
    }

    public static String combinePublicKeys(List<? extends ECPoint> keys, boolean compressed) throws TorusUtilError {
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

    public static PrivateKeyData generateKeyData(String privateKey) {
        BigInteger scalar = new BigInteger(privateKey, 16);
        BigInteger randomNonce = new BigInteger(1, getRandomBytes(32));
        randomNonce = new BigInteger(addLeading0sForLength64(randomNonce.toString(16)), 16);

        ECDomainParameters params = new ECDomainParameters(curveParams);
        BigInteger oAuthKey = scalar.subtract(randomNonce).mod(curveParams.getN());
        ECPrivateKeyParameters oAuthPrivKey = new ECPrivateKeyParameters(oAuthKey, params);
        ECPoint oAuthPubPoint = curveParams.getG().multiply(oAuthPrivKey.getD());
        ECPublicKeyParameters oAuthPubKey = new ECPublicKeyParameters(oAuthPubPoint, params);

        ECPrivateKeyParameters finalPrivKey = new ECPrivateKeyParameters(scalar, params);
        ECPoint finalPubPoint = curveParams.getG().multiply(finalPrivKey.getD());
        ECPublicKeyParameters finalPubKey = new ECPublicKeyParameters(finalPubPoint,params);

        return new PrivateKeyData(
                oAuthKey.toString(16),
                Hex.toHexString(oAuthPubKey.getQ().getEncoded(false)),
                randomNonce.toString(16),
                oAuthKey.toString(16),
                Hex.toHexString(oAuthPubKey.getQ().getEncoded(false)),
                privateKey,
                Hex.toHexString(finalPubKey.getQ().getEncoded(false))
        );
    }

    public static NonceMetadataParams generateNonceMetadataParams(String operation, BigInteger privateKey, BigInteger nonce, BigInteger serverTimeOffset) {
        long timeSeconds = System.currentTimeMillis() / 1000L;
        BigInteger timestamp = serverTimeOffset.add(BigInteger.valueOf(timeSeconds));

        // Create ECKeyPair from private key
        ECKeyPair ecKeyPair = ECKeyPair.create(privateKey);

        // Serialize public key into padded X and Y coordinates
        String derivedPubKeyString = Utils.padLeft(ecKeyPair.getPublicKey().toString(16), '0', 128);
        String derivedPubKeyX = derivedPubKeyString.substring(0, 64);
        String derivedPubKeyY = derivedPubKeyString.substring(64);

        // Create SetNonceData object with operation and timestamp
        SetNonceData setNonceData = new SetNonceData(operation, timestamp.toString(16));
        if (nonce != null) {
            setNonceData.setData(Utils.padLeft(nonce.toString(16), '0', 64));
        }

        // Convert SetNonceData object to JSON string
        /*ObjectMapper objectMapper = new ObjectMapper();
        String encodedData = objectMapper.writeValueAsString(setNonceData);*/
        Gson gson = new Gson();
        String encodedData = gson.toJson(setNonceData);

        // Hash the JSON string using keccak256 (SHA-3)
        byte[] hashedData = Hash.sha3(encodedData.getBytes(StandardCharsets.UTF_8));

        // Sign the hashed data using ECDSA with the private key
        ECDSASignature signature = ecKeyPair.sign(hashedData);

        // Format the signature into a padded hexadecimal string
        String sig = Utils.padLeft(signature.r.toString(16), '0', 64) +
                Utils.padLeft(signature.s.toString(16), '0', 64) +
                Utils.padLeft("", '0', 2); // Assuming padding to ensure consistent length

        // Convert the hexadecimal signature string to bytes
        byte[] sigBytes = Utils.toByteArray(new BigInteger(sig, 16));

        // Encode the signature bytes to Base64
        String finalSig = new String(Base64.encodeBytesToBytes(sigBytes), StandardCharsets.UTF_8);

        // Return a new NonceMetadataParams object with the derived values
        return new NonceMetadataParams(derivedPubKeyX, derivedPubKeyY, setNonceData,
                Base64.encodeBytes(encodedData.getBytes(StandardCharsets.UTF_8)), finalSig);
    }

    public static List<ImportedShare> generateShares(KeyType keyType, BigInteger serverTimeOffset, List<BigInteger> nodeIndexes, List<TorusNodePub> nodePubKeys, String privateKey) throws Exception {
        if (keyType != KeyType.secp256k1) {
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
            Ecies encryptedMsg = Encryption.encrypt(nodePub.getBytes(), Utils.padLeft(shareInfo.getShare().toString(16), '0', 64));
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
                    nonceParams.getEncodedData(), nonceParams.getSignature());

            sharesData.add(importShare);
        }
        return sharesData;
    }
}

