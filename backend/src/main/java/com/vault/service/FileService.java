package com.vault.service;

import com.vault.crypto.AesGcmUtil;
import com.vault.crypto.HashUtil;
import com.vault.crypto.RsaOaepUtil;
import com.vault.entity.StoredFile;
import com.vault.entity.User;
import com.vault.exception.FileIntegrityException;
import com.vault.exception.FileStorageException;
import com.vault.exception.VaultFileNotFoundException;
import com.vault.repository.StoredFileRepository;
import com.vault.security.CurrentUserService;
import com.vault.security.RsaKeyStoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

/**
 * Upload: SHA-256(plaintext) -> fresh AES-256 key + IV -> AES-GCM -> disk
 * -> RSA-OAEP wrap key -> StoredFile row. Ownership always from the
 * authenticated principal, never from client input.
 */
@Service
public class FileService {

    private static final Logger log = LoggerFactory.getLogger(FileService.class);

    private final StoredFileRepository files;
    private final CurrentUserService currentUser;
    private final RsaKeyStoreService keys;
    private final Path storageDir;

    /** Decrypted download payload (bytes held transiently, never logged). */
    public record DecryptedFile(String originalFilename, byte[] content) {}

    public FileService(StoredFileRepository files, CurrentUserService currentUser,
                       RsaKeyStoreService keys,
                       @Value("${app.storage.dir:./storage}") String storageDir) {
        this.files = files;
        this.currentUser = currentUser;
        this.keys = keys;
        this.storageDir = Path.of(storageDir);
        try {
            Files.createDirectories(this.storageDir);
        } catch (Exception e) {
            throw new FileStorageException("Could not initialize storage directory", e);
        }
    }

    public StoredFile upload(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new FileStorageException("No file provided");
        }
        User owner = currentUser.currentUser();
        try {
            byte[] plain = file.getInputStream().readAllBytes();
            String sha256 = HashUtil.sha256Hex(plain);

            SecretKey aesKey = AesGcmUtil.generateKey();
            byte[] iv = AesGcmUtil.generateIv();
            byte[] cipher = AesGcmUtil.encrypt(plain, aesKey, iv);
            // Drop plaintext reference ASAP (10MB cap bounds memory; documented in README).
            plain = null;

            String storedName = UUID.randomUUID() + ".enc";
            Files.write(storageDir.resolve(storedName), cipher);

            byte[] wrappedKey = RsaOaepUtil.encrypt(aesKey.getEncoded(), keys.getPublicKey());

            String original = StringUtils.cleanPath(
                    file.getOriginalFilename() == null ? "file" : file.getOriginalFilename());
            StoredFile saved = files.save(new StoredFile(original, storedName,
                    wrappedKey, iv, sha256, file.getSize(), owner));
            log.info("File uploaded id={} size={}", saved.getId(), saved.getFileSize());
            return saved;
        } catch (FileStorageException e) {
            throw e;
        } catch (Exception e) {
            throw new FileStorageException("File upload failed", e);
        }
    }

    public List<StoredFile> listMine() {
        return files.findByOwner(currentUser.currentUser());
    }

    public DecryptedFile download(long id) {
        StoredFile meta = files.findByIdAndOwner(id, currentUser.currentUser())
                .orElseThrow(VaultFileNotFoundException::new);
        try {
            Path blob = storageDir.resolve(meta.getStoredFilename()).normalize();
            // Contain reads to the storage dir even if DB metadata was tampered with.
            if (!blob.startsWith(storageDir.normalize()) || !Files.exists(blob)) {
                throw new FileIntegrityException("File integrity verification failed");
            }
            byte[] cipher = Files.readAllBytes(blob);
            byte[] aesBytes = RsaOaepUtil.decrypt(meta.getEncryptedAesKey(), keys.getPrivateKey());
            SecretKey aesKey = AesGcmUtil.keyFromBytes(aesBytes);
            byte[] plain;
            try {
                plain = AesGcmUtil.decrypt(cipher, aesKey, meta.getIv());
            } catch (Exception gcmFail) {
                // AES-GCM tag rejected the ciphertext: tampered/corrupt — no partial data.
                throw new FileIntegrityException("File integrity verification failed");
            }
            if (!HashUtil.sha256Hex(plain).equalsIgnoreCase(meta.getSha256Hash())) {
                throw new FileIntegrityException("File integrity verification failed");
            }
            return new DecryptedFile(meta.getOriginalFilename(), plain);
        } catch (FileIntegrityException | VaultFileNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new FileStorageException("File download failed", e);
        }
    }

    public void delete(long id) {
        StoredFile meta = files.findByIdAndOwner(id, currentUser.currentUser())
                .orElseThrow(VaultFileNotFoundException::new);
        try {
            Files.deleteIfExists(storageDir.resolve(meta.getStoredFilename()).normalize());
        } catch (Exception e) {
            log.warn("Could not delete blob for file id={}", id);
        }
        files.delete(meta);
    }
}
