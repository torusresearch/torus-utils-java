package org.torusresearch.torusutilstest.utils;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PemUtils {
    private static byte[] parsePEMFile(File pemFile) throws IOException {
        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        PemReader reader = new PemReader(new FileReader(pemFile));
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }

    @SuppressWarnings("unused")
    private static PublicKey getPublicKey(byte[] keyBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = null;
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = null;
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        privateKey = kf.generatePrivate(keySpec);

        return privateKey;
    }

    public static PrivateKey readPrivateKeyFromFile(String filepath, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = PemUtils.parsePEMFile(new File(filepath));
        return PemUtils.getPrivateKey(bytes, algorithm);
    }

}