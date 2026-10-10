package com.vault.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM utility.
 * - 256-bit key, 96-bit (12 byte) IV, 128-bit auth tag.
 * - NEVER reuse an IV with the same key (we generate a fresh IV per file).
 * - NEVER uses ECB.
 */
public final class AesGcmUtil {

    public static final int AES_KEY_BITS = 256;
    public static final int GCM_IV_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private AesGcmUtil() {}

    /** Cryptographically secure random 256-bit AES key. Never hard-coded. */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS, SECURE_RANDOM);
        return kg.generateKey();
    }

    /** Cryptographically secure random 12-byte IV/nonce. Fresh per encryption. */
    public static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_BYTES];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    public static SecretKey keyFromBytes(byte[] raw) {
        if (raw == null || raw.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes");
        }
        return new SecretKeySpec(raw, "AES");
    }

    public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv), SECURE_RANDOM);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ciphertext); // throws AEADBadTagException if tampered
    }
}
