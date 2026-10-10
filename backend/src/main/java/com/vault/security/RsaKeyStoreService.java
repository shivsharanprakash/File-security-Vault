package com.vault.security;

import com.vault.crypto.RsaOaepUtil;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Owns the application RSA-2048 key pair used to wrap AES file keys.
 * Persisted as two files under keys/: public (X.509 DER) + private (PKCS#8 DER).
 * Private file gets owner-only permissions where the OS supports it.
 * Generated ONCE then reloaded, so wrapped AES keys stay decryptable.
 * Private key is NEVER exposed via REST, logs, or the database.
 */
@Service
public class RsaKeyStoreService {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyStoreService.class);

    private final Path publicPath;
    private final Path privatePath;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RsaKeyStoreService(
            @Value("${app.keys.dir:./keys}") String keysDir,
            @Value("${app.keystore.password:${VAULT_KEYSTORE_PASSWORD:changeit-dev-only}}") String password) {
        // password retained in config for a future PKCS#12 upgrade path; file perms guard the key today.
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("keystore password must not be blank");
        }
        Path dir = Path.of(keysDir);
        this.publicPath = dir.resolve("vault-rsa-public.der");
        this.privatePath = dir.resolve("vault-rsa-private.der");
    }

    /** Generate-once / load-existing before any file endpoint can run. */
    @PostConstruct
    public void initialize() {
        try {
            Files.createDirectories(privatePath.getParent());
            if (Files.exists(privatePath) && Files.exists(publicPath)) {
                load();
                log.info("RSA keypair loaded from keys directory");
            } else {
                generateAndStore();
                log.info("New RSA-2048 keypair generated and stored");
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize RSA keys", e);
        }
    }

    private void load() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(
                new PKCS8EncodedKeySpec(Files.readAllBytes(privatePath)));
        this.publicKey = kf.generatePublic(
                new X509EncodedKeySpec(Files.readAllBytes(publicPath)));
    }

    private void generateAndStore() throws Exception {
        KeyPair kp = RsaOaepUtil.generateKeyPair();
        Files.write(publicPath, kp.getPublic().getEncoded());
        Files.write(privatePath, kp.getPrivate().getEncoded());
        restrictPrivateKey();
        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
    }

    private void restrictPrivateKey() {
        try {
            java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                    java.util.EnumSet.of(
                            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(privatePath, perms);
        } catch (UnsupportedOperationException | java.io.IOException ignored) {
            // Windows ACLs: best effort only; .gitignore still keeps it out of git.
        }
    }

    public PublicKey getPublicKey() { return publicKey; }
    public PrivateKey getPrivateKey() { return privateKey; }

    /** SHA-256 fingerprint of the public key — used by tests to prove reload. */
    public String publicKeyFingerprint() throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(publicKey.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}

