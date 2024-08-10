package org.torusresearch.torusutilstest.helpers;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.apis.Ecies;
import org.torusresearch.torusutils.helpers.Encryption.Encryption;
import org.torusresearch.torusutils.helpers.KeyUtils;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;

public class AES256CBC {
    @Test
    public void testECDH() throws Exception {
        KeyPair secret = KeyUtils.generateKeyPair();
        KeyPair secret2 = KeyUtils.generateKeyPair();

        byte[] shared = Encryption.ecdh(KeyUtils.serializePrivateKey(secret.getPrivate()), (KeyUtils.serializePublicKey(secret2.getPublic(), false)));
        byte[] shared2 = Encryption.ecdh(KeyUtils.serializePrivateKey(secret2.getPrivate()), (KeyUtils.serializePublicKey(secret.getPublic(), false)));
        assertArrayEquals(shared, shared2);
}
    @Test
    public void testEncryption() throws Exception {
        KeyPair keypair = KeyUtils.generateKeyPair();
        String payload =  "Hello World";

        Ecies encrypted = Encryption.encrypt(KeyUtils.serializePublicKey(keypair.getPublic(), false), payload);
        String decrypted = Encryption.decrypt(Hex.toHexString(KeyUtils.serializePrivateKey(keypair.getPrivate())), encrypted);

        assertEquals(payload, decrypted);
    }
}
