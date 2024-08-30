package org.torusresearch.torusutilstest.helpers;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.torusresearch.torusutils.helpers.KeyUtils;

public class TestGenerateEthereumAddress {
    @Test
    public void testGenerateAddressFromPublicKey() throws Exception {
        String fullAddress = "04238569d5e12caf57d34fb5b2a0679c7775b5f61fd18cd69db9cc600a651749c3ec13a9367380b7a024a67f5e663f3afd40175c3223da63f6024b05d0bd9f292e";
        String[] coords = KeyUtils.getPublicKeyCoords(fullAddress);
        String etherAddress = KeyUtils.generateAddressFromPubKey(coords[0], coords[1]);
        String finalAddress = "0x048975d4997D7578A3419851639c10318db430b6";
        assertEquals(etherAddress, finalAddress);
    }
}
