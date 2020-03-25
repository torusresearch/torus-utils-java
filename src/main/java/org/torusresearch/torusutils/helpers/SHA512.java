package org.torusresearch.torusutils.helpers;

import java.security.MessageDigest;

public class SHA512 {
    public static byte[] digest(byte[] buf) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.update(buf);
            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
