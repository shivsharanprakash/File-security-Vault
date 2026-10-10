package com.vault.crypto;

import java.io.InputStream;
import java.security.MessageDigest;

/**
 * SHA-256 helper for integrity (not encryption).
 */
public final class HashUtil {

    private HashUtil() {}

    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public static byte[] sha256(InputStream in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            md.update(buf, 0, n);
        }
        return md.digest();
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String sha256Hex(byte[] data) throws Exception {
        return toHex(sha256(data));
    }
}
