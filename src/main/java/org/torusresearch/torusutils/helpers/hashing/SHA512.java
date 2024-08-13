package org.torusresearch.torusutils.helpers.hashing;

import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512 {
    public static byte[] digest(@NotNull byte[] buf) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(buf);
        return digest.digest();
    }
}
