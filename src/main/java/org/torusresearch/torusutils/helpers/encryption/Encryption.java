package org.torusresearch.torusutils.helpers.encryption;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.types.common.ecies.Ecies;
import org.torusresearch.torusutils.types.common.ecies.EciesHexOmitCipherText;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.hashing.SHA512;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
    static final protected Provider provider  = new BouncyCastleProvider();

    public static byte[] ecdh (@NotNull byte[] dataPrv, @NotNull byte[] dataPub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", provider);
        ka.init(KeyUtils.deserializePrivateKey(dataPrv));
        ka.doPhase(KeyUtils.deserializePublicKey(dataPub), true);
        return ka.generateSecret();
    }

    public static Ecies encrypt(@NotNull byte[] publicKey, @NotNull String plaintext) throws Exception {
        KeyPair ephemeral = KeyUtils.generateKeyPair();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        byte[] shared = ecdh(KeyUtils.serializePrivateKey(ephemeral.getPrivate()), publicKey);
        byte[] hash = SHA512.digest(shared);
        byte[] aesKey = new byte[32];
        System.arraycopy(hash, 0, aesKey, 0, 32);
        byte[] macKey = new byte[32];
        System.arraycopy(hash, 32, macKey, 0, 32);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv); // 16 bytes
        outputStream.write(publicKey); // 65 bytes
        outputStream.write(cipherText);

        byte[] dataToMac = outputStream.toByteArray();

        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(macKey));
        byte[] finalMac = new byte[hmac.getMacSize()];
        hmac.update(dataToMac, 0, dataToMac.length);
        hmac.doFinal(finalMac, 0);
        return new Ecies(Hex.toHexString(iv), Hex.toHexString(KeyUtils.serializePublicKey(ephemeral.getPublic(),false)),Hex.toHexString(cipherText), Hex.toHexString(finalMac));
    }

    public static String decrypt(@NotNull String privateKeyHex, @NotNull Ecies ecies) throws Exception {
        byte[] shared = ecdh(Hex.decode(privateKeyHex), Hex.decode(ecies.getEphemPublicKey()));
        byte[] sha512hash = SHA512.digest(shared);
        SecretKeySpec aesKey = new SecretKeySpec(Arrays.copyOf(sha512hash, 32), "AES");

        byte[] iv = Hex.decode(ecies.getIv());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] cipherText = Hex.decode(ecies.getCiphertext());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }


    public static String decryptNodeData(@NotNull EciesHexOmitCipherText eciesData, @NotNull String ciphertextHex, @NotNull String privKey) throws Exception {
        Ecies eciesOpts = new Ecies(
                eciesData.getIv(),
                eciesData.getEphemPublicKey(),
                ciphertextHex,
                eciesData.getMac()
        );
        return decrypt(privKey, eciesOpts);
    }
}
