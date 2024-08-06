package org.torusresearch.torusutils.helpers;

import org.torusresearch.torusutils.apis.Ecies;
import org.torusresearch.torusutils.apis.EciesHexOmitCipherText;
import org.torusresearch.torusutils.types.TorusException;

import java.math.BigInteger;
import java.security.Key;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES_256_CBC {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static String ivKey = "";
    public static String macKey = "";

    /**
     * Utility method to convert a BigInteger to a byte array in unsigned
     * format as needed in the handshake messages. BigInteger uses
     * 2's complement format, i.e. it prepends an extra zero if the MSB
     * is set. We remove that.
     */
    public static byte[] toByteArray(BigInteger bi) {
        byte[] b = bi.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            int n = b.length - 1;
            byte[] newArray = new byte[n];
            System.arraycopy(b, 1, newArray, 0, n);
            b = newArray;
        }
        return b;
    }

    public static byte[] toByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String encrypt(String publicKeyHex, byte[] src) throws TorusException {
        Cipher cipher;
        try {
            String privateKeyHex = KeyUtils.generateSecret();
            String encryptionIvHex = Utils.convertByteToHexadecimal(Utils.getRandomBytes(16));
            byte[] hash = SHA512.digest(toByteArray(ecdh(privateKeyHex, publicKeyHex)));
            byte[] encKeyBytes = Arrays.copyOfRange(hash, 0, 32);
            /*AES_ENCRYPTION_KEY = encKeyBytes;
            ENCRYPTION_IV = toByteArray(encryptionIvHex);*/
            Key keySpec = new SecretKeySpec(encKeyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(toByteArray(encryptionIvHex));
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return Base64.encodeBytes(cipher.doFinal(src));
        } catch (Exception e) {
            e.printStackTrace();
            throw new TorusException("Torus Internal Error", e);
        }
    }

    public static String encryptAndHex(String publicKeyHex, byte[] src) throws TorusException {
        Cipher cipher;
        try {
            String privateKeyHex = KeyUtils.generateSecret();
            String encryptionIvHex = Utils.convertByteToHexadecimal(Utils.getRandomBytes(16));
            byte[] hash = SHA512.digest(toByteArray(ecdh(privateKeyHex, publicKeyHex)));
            byte[] encKeyBytes = Arrays.copyOfRange(hash, 0, 32);
            ivKey = encryptionIvHex;
            macKey = Utils.bytesToHex(encKeyBytes);
            Key keySpec = new SecretKeySpec(encKeyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(toByteArray(encryptionIvHex));
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return Utils.convertByteToHexadecimal(cipher.doFinal(src));
        } catch (Exception e) {
            e.printStackTrace();
            throw new TorusException("Torus Internal Error", e);
        }
    }

    public static byte[] decryptNodeData(EciesHexOmitCipherText eciesData, String ciphertextHex, String privKey) throws Exception {
        Ecies eciesOpts = new Ecies(
                eciesData.getIv(),
                eciesData.getEphemPublicKey(),
                ciphertextHex,
                eciesData.getMac()
        );

        byte[] decryptedSigBuffer = decrypt(privKey, eciesOpts);
        return decryptedSigBuffer;
    }

    public static byte[] decrypt(String privateKeyHex, Ecies ecies) throws TorusException {
        Cipher cipher;
        try {
            byte[] hash = SHA512.digest(toByteArray(ecdh(privateKeyHex, ecies.getEphemPublicKey())));
            byte[] encKeyBytes = Arrays.copyOfRange(hash, 0, 32);
            Key keySpec = new SecretKeySpec(encKeyBytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(toByteArray(ecies.getIv()));
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(Base64.decode(Base64.encodeBytes(toByteArray(new BigInteger(ecies.getCiphertext(), 16)))));
        } catch (Exception e) {
            e.printStackTrace();
            throw new TorusException("Torus Internal Error", e);
        }
    }

    /*public byte[] decryptHex(String src) throws TorusException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, makeKey(), makeIv());
            return cipher.doFinal(toByteArray(src));
        } catch (Exception e) {
            e.printStackTrace();
            throw new TorusException("Torus Internal Error", e);
        }
    }*/

    private static BigInteger ecdh(String privateKeyHex, String ephemPublicKeyHex) {
        String affineX = ephemPublicKeyHex.substring(2, 66);
        String affineY = ephemPublicKeyHex.substring(66);

        ECPointArithmetic ecPoint = new ECPointArithmetic(new EllipticCurve(
                new ECFieldFp(new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")),
                new BigInteger("0"),
                new BigInteger("7")), new BigInteger(affineX, 16), new BigInteger(affineY, 16), null);
        return ecPoint.multiply(new BigInteger(privateKeyHex, 16)).getX();
    }
}
