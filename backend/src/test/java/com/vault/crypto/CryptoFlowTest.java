package com.vault.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Proves the hybrid-encryption core before we build any API:
 * AES-256-GCM for the file, RSA-OAEP only for the AES key, SHA-256 for integrity.
 */
class CryptoFlowTest {

    @Test
    void aesEncryptDecryptRoundTrip() throws Exception {
        SecretKey key = AesGcmUtil.generateKey();
        byte[] iv = AesGcmUtil.generateIv();
        byte[] plain = "INS mini-project: hello vault!".getBytes();

        byte[] cipher = AesGcmUtil.encrypt(plain, key, iv);
        assertFalse(Arrays.equals(plain, cipher));

        byte[] recovered = AesGcmUtil.decrypt(cipher, key, iv);
        assertArrayEquals(plain, recovered);
    }

    @Test
    void tamperedCiphertextMustFailGcmAuth() throws Exception {
        SecretKey key = AesGcmUtil.generateKey();
        byte[] iv = AesGcmUtil.generateIv();
        byte[] cipher = AesGcmUtil.encrypt("tamper me".getBytes(), key, iv);

        cipher[0] ^= 0x01; // flip one bit -> GCM tag check must fail
        assertThrows(Exception.class, () -> AesGcmUtil.decrypt(cipher, key, iv));
    }

    @Test
    void rsaWrapsUnwrapsAesKey() throws Exception {
        KeyPair kp = RsaOaepUtil.generateKeyPair();
        SecretKey aes = AesGcmUtil.generateKey();

        byte[] wrapped = RsaOaepUtil.encrypt(aes.getEncoded(), kp.getPublic());
        // RSA-2048 OAEP output is 256 bytes even though the AES key is 32 bytes
        assertEquals(256, wrapped.length);

        byte[] unwrapped = RsaOaepUtil.decrypt(wrapped, kp.getPrivate());
        assertArrayEquals(aes.getEncoded(), unwrapped);
    }

    @Test
    void sha256DetectsModification() throws Exception {
        byte[] original = "original file bytes".getBytes();
        byte[] modified = "original file byteS".getBytes();
        String h1 = HashUtil.sha256Hex(original);
        String h2 = HashUtil.sha256Hex(modified);
        assertEquals(64, h1.length()); // 256 bits = 64 hex chars
        assertNotEquals(h1, h2);
    }

    @Test
    void fullHybridFlow_likeUploadThenDownload() throws Exception {
        // ---- UPLOAD side ----
        byte[] fileBytes = "my secret notes".getBytes();
        String storedHash = HashUtil.sha256Hex(fileBytes);

        SecretKey aesKey = AesGcmUtil.generateKey();
        byte[] iv = AesGcmUtil.generateIv();
        byte[] encryptedFile = AesGcmUtil.encrypt(fileBytes, aesKey, iv);

        KeyPair kp = RsaOaepUtil.generateKeyPair();
        byte[] encryptedAesKey = RsaOaepUtil.encrypt(aesKey.getEncoded(), kp.getPublic());

        // ---- DOWNLOAD side ----
        byte[] aesBytes = RsaOaepUtil.decrypt(encryptedAesKey, kp.getPrivate());
        SecretKey restored = AesGcmUtil.keyFromBytes(aesBytes);
        byte[] decrypted = AesGcmUtil.decrypt(encryptedFile, restored, iv);

        assertEquals(storedHash, HashUtil.sha256Hex(decrypted));
        assertArrayEquals(fileBytes, decrypted);
    }
}
