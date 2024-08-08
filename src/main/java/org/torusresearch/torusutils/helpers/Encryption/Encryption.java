package org.torusresearch.torusutils.helpers.Encryption;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.torusresearch.torusutils.apis.Ecies;
import org.torusresearch.torusutils.apis.EciesHexOmitCipherText;
import org.torusresearch.torusutils.helpers.SHA512;
import org.torusresearch.torusutils.helpers.Utils;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
    static final protected Provider provider  = new BouncyCastleProvider();

    final protected static char[] hexArray = "0123456789abcdef".toCharArray();

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", provider);
            kpgen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
            return kpgen.generateKeyPair();
    }
    public static byte [] savePublicKey (PublicKey key) {
            org.bouncycastle.jce.interfaces.ECPublicKey eckey = (ECPublicKey)key;
            return eckey.getQ().getEncoded(true);
    }

    public static PublicKey loadPublicKey (byte [] data) throws Exception
    {
            org.bouncycastle.jce.spec.ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
            org.bouncycastle.jce.spec.ECPublicKeySpec pubKey = new org.bouncycastle.jce.spec.ECPublicKeySpec(
                    params.getCurve().decodePoint(data), params);
            KeyFactory kf = KeyFactory.getInstance("ECDH", provider);
            return kf.generatePublic(pubKey);
    }

    public static byte [] savePrivateKey (PrivateKey key) {
            ECPrivateKey eckey = (ECPrivateKey)key;
            return eckey.getD().toByteArray();
    }
    public static PrivateKey loadPrivateKey (byte [] data) throws Exception {
            ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
            org.bouncycastle.jce.spec.ECPrivateKeySpec prvkey = new org.bouncycastle.jce.spec.ECPrivateKeySpec(new BigInteger(data), params);
            KeyFactory kf = KeyFactory.getInstance("ECDH", provider);
            return kf.generatePrivate(prvkey);
    }

    public static byte[] ecdh (byte[] dataPrv, byte[] dataPub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", provider);
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        return ka.generateSecret();
    }

    public static Ecies encrypt(byte[] publicKey, String plaintext) throws Exception {
        KeyPair ephemeral = Encryption.generateKeyPair();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", provider);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        byte[] shared = ecdh(savePrivateKey(ephemeral.getPrivate()), savePublicKey(loadPublicKey(publicKey)));
        byte[] hash = SHA512.digest(shared);
        byte[] aesKey = new byte[32];
        System.arraycopy(hash, 0, aesKey, 0, 32);
        byte[] macKey = new byte[32];
        System.arraycopy(hash, 32, macKey, 0, 32);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));

        byte[] cipherText = Hex.encode(cipher.doFinal(plaintext.getBytes()));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv); // 16 bytes
        outputStream.write(savePublicKey(loadPublicKey(publicKey))); // 65 bytes
        outputStream.write(cipherText);

        byte[] dataToMac = outputStream.toByteArray();

        return new Ecies(Hex.toHexString(iv), Hex.toHexString(savePublicKey(loadPublicKey(publicKey))),Hex.toHexString(cipherText), Hex.toHexString(dataToMac));
    }

    public static String decrypt(String privateKeyHex, Ecies ecies) throws Exception {
        byte[] shared = ecdh(savePrivateKey(loadPrivateKey(Hex.decode(privateKeyHex))), savePublicKey(loadPublicKey(Hex.decode(ecies.getEphemPublicKey()))));
        byte[] sha512hash = SHA512.digest(shared);
        SecretKeySpec aesKey = new SecretKeySpec(Arrays.copyOf(sha512hash, 32), "AES");

        byte[] iv = Hex.decode(ecies.getIv());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] cipherText = Hex.decode(ecies.getCiphertext());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        return cipher.doFinal(cipherText).toString();
    }


    public static String decryptNodeData(EciesHexOmitCipherText eciesData, String ciphertextHex, String privKey) throws Exception {
        Ecies eciesOpts = new Ecies(
                eciesData.getIv(),
                eciesData.getEphemPublicKey(),
                ciphertextHex,
                eciesData.getMac()
        );
        return decrypt(privKey, eciesOpts);
    }
}
