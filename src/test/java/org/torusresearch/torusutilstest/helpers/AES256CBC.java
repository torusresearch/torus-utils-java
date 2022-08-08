package org.torusresearch.torusutilstest.helpers;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class AES256CBC {

    @Test
    public void testLeadingZeroes() {
        // This combination of private and public keys resuts in an SHA512 hash with a leading zero
        String privateKey = "dec95a4ffa406daedd079956f1e43fb91baefdad00990699642474eeb09a5a90";
        String publicKey  = "a6262a5650a9666195098c2e15e8eb451a755eb59ea2d1b437d11d9113f4d356bd479f01d29850b77fa6357628d2ed0fa0d8230620472b91f21db1c2c6e7def";

        // Leading zeroes in IV
        String iv = "0023456789ABCDEF0123456789ABCDEF";

        byte[] payload = "Hello World".getBytes(StandardCharsets.UTF_8);

        try {
            org.torusresearch.torusutils.helpers.AES256CBC aes256cbc = new org.torusresearch.torusutils.helpers.AES256CBC(privateKey, publicKey, iv);
            String encrypted = aes256cbc.encrypt(payload);
            byte[] decrypted = aes256cbc.decrypt(encrypted);

            assertArrayEquals(payload, decrypted);
        } catch (Exception e) {
            assertFalse(true);
        }
    }


}
