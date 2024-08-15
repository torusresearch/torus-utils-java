package org.torusresearch.torusutilstest.helpers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.encryption.Encryption;
import org.torusresearch.torusutils.types.common.ecies.Ecies;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public class TestAES256CBC {
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
        String hexEncoded = Hex.toHexString(payload.getBytes());
        Ecies encrypted = Encryption.encrypt(KeyUtils.serializePublicKey(keypair.getPublic(), false), hexEncoded);
        String decrypted = new String(Encryption.decrypt(Hex.toHexString(KeyUtils.serializePrivateKey(keypair.getPrivate())), encrypted), StandardCharsets.UTF_8);
        String decryptedNodeData = Encryption.decryptNodeData(encrypted.omitCipherText(), encrypted.ciphertext, Hex.toHexString(KeyUtils.serializePrivateKey(keypair.getPrivate())));

        assertEquals(payload, decrypted);
        assertEquals(hexEncoded, decryptedNodeData);
    }
}
