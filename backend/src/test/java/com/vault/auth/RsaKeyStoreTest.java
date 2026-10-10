package com.vault.auth;

import com.vault.security.RsaKeyStoreService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Constructor;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Proves the restart-safety rule: generating once, then reloading the SAME
 * keypair from the PKCS#12 keystore (else old AES keys would be lost).
 */
class RsaKeyStoreTest {

    @TempDir
    Path tempKeysDir;

    private RsaKeyStoreService newService() throws Exception {
        Constructor<RsaKeyStoreService> ctor =
                RsaKeyStoreService.class.getConstructor(String.class, String.class);
        return ctor.newInstance(tempKeysDir.toString(), "test-keystore-pass");
    }

    @Test
    void keypairGeneratedThenReloadedAcrossRestart() throws Exception {
        RsaKeyStoreService firstBoot = newService();
        firstBoot.initialize();
        assertNotNull(firstBoot.getPrivateKey());
        assertNotNull(firstBoot.getPublicKey());
        String fingerprint1 = firstBoot.publicKeyFingerprint();
        assertTrue(
                java.nio.file.Files.exists(tempKeysDir.resolve("vault-rsa-private.der")));
        assertTrue(
                java.nio.file.Files.exists(tempKeysDir.resolve("vault-rsa-public.der")));

        // Simulate a restart: brand-new bean over the SAME keystore dir.
        RsaKeyStoreService secondBoot = newService();
        secondBoot.initialize();
        String fingerprint2 = secondBoot.publicKeyFingerprint();

        assertEquals(fingerprint1, fingerprint2, "keypair must survive restarts");

        // And the reloaded pair must actually wrap/unwrap.
        byte[] secret = "aes-key-bytes-32.........".getBytes();
        byte[] wrapped = com.vault.crypto.RsaOaepUtil.encrypt(secret, secondBoot.getPublicKey());
        assertArrayEquals(secret,
                com.vault.crypto.RsaOaepUtil.decrypt(wrapped, secondBoot.getPrivateKey()));
    }
}
