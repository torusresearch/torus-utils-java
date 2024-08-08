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

        byte[] shared = Encryption.ecdh(Encryption.savePrivateKey(secret.getPrivate()), (Encryption.savePublicKey(secret2.getPublic())));
        byte[] shared2 = Encryption.ecdh(Encryption.savePrivateKey(secret2.getPrivate()), (Encryption.savePublicKey(secret.getPublic())));
        assertArrayEquals(shared, shared2);
}
    @Test
    public void testEncryption() throws Exception {
        KeyPair keypair = Encryption.generateKeyPair();
        String payload =  "Hello World";

        Ecies encrypted = Encryption.encrypt(Encryption.savePublicKey(keypair.getPublic()), payload);
        String decrypted = Encryption.decrypt(Hex.toHexString(Encryption.savePrivateKey(keypair.getPrivate())), encrypted);

        assertEquals(payload, decrypted);
    }


}
