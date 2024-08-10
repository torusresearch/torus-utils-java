package org.torusresearch.torusutilstest.helpers;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.apis.Ecies;
import org.torusresearch.torusutils.helpers.Encryption.Encryption;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;

public class AES256CBC {
    @Test
    public void testECDH() throws Exception {
        KeyPair secret = Encryption.generateKeyPair();
        KeyPair secret2 = Encryption.generateKeyPair();

        byte[] shared = Encryption.ecdh(Encryption.serializePrivateKey(secret.getPrivate()), (Encryption.serializePublicKey(secret2.getPublic(), false)));
        byte[] shared2 = Encryption.ecdh(Encryption.serializePrivateKey(secret2.getPrivate()), (Encryption.serializePublicKey(secret.getPublic(), false)));
        assertArrayEquals(shared, shared2);
}
    @Test
    public void testEncryption() throws Exception {
        KeyPair keypair = Encryption.generateKeyPair();
        String payload =  "Hello World";

        Ecies encrypted = Encryption.encrypt(Encryption.serializePublicKey(keypair.getPublic(), false), payload);
        String decrypted = Encryption.decrypt(Hex.toHexString(Encryption.serializePrivateKey(keypair.getPrivate())), encrypted);

        assertEquals(payload, decrypted);
    }


}
