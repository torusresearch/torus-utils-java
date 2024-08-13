package org.torusresearch.torusutilstest.helpers;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.types.common.ecies.Ecies;
import org.torusresearch.torusutils.helpers.Encryption.Encryption;
import org.torusresearch.torusutils.helpers.KeyUtils;
import org.torusresearch.torusutils.helpers.Utils;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class AES256CBC {

    //TODO: Move this test to proper place
    @Test
    public void testKCombinations() throws Exception {
        List<Integer> set = new ArrayList<>();
        List<List<Integer>> allCombis = Utils.kCombinations(set, 0);
        assertEquals(allCombis.size(), 0);

        set.add(0);
        set.add(1);
        set.add(2);
        set.add(3);
        set.add(4);
        set.add(5);


        allCombis = Utils.kCombinations(set, 10);
        assertEquals(allCombis.size(), 0);

        allCombis = Utils.kCombinations(set, 6);
        assertEquals(allCombis.size(), 1);

        allCombis = Utils.kCombinations(set, 1);
        assertEquals(allCombis.size(), 6);

        allCombis = Utils.kCombinations(set, 2);
        assertEquals(allCombis.size(), 15);

        set.remove(0);
        allCombis = Utils.kCombinations(set, 3);
        assertEquals(allCombis.size(), 10);
    }

    //TODO: Move this test to proper place
    @Test
    public void testGenerateAddressFromPublicKey() throws Exception {
        String fullAddress = "04238569d5e12caf57d34fb5b2a0679c7775b5f61fd18cd69db9cc600a651749c3ec13a9367380b7a024a67f5e663f3afd40175c3223da63f6024b05d0bd9f292e";
        String[] coords = KeyUtils.getPublicKeyCoords(fullAddress);
        String etherAddress = KeyUtils.generateAddressFromPubKey(coords[0], coords[1]);
        String finalAddress = "0x048975d4997D7578A3419851639c10318db430b6";
        assertEquals(etherAddress, finalAddress);
    }

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
        String decryptedNodeData = Encryption.decryptNodeData(encrypted.omitCipherText(), encrypted.getCiphertext(), Hex.toHexString(KeyUtils.serializePrivateKey(keypair.getPrivate())));

        assertEquals(payload, decrypted);
        assertEquals(payload, decryptedNodeData);
    }
}
