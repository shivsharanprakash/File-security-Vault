package com.vault.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Metadata for ONE encrypted file on disk.
 * Actual ciphertext lives in the storage directory (Phase 4);
 * only metadata + wrapped key material lives in SQLite.
 */
@Entity
@Table(name = "stored_files")
public class StoredFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "original_filename", nullable = false)
    private String originalFilename;

    @Column(name = "stored_filename", nullable = false, unique = true)
    private String storedFilename;

    /** RSA-OAEP-encrypted AES-256 key (256 bytes for RSA-2048). BLOB in SQLite. */
    @Column(name = "encrypted_aes_key", nullable = false)
    private byte[] encryptedAesKey;

    /** AES-GCM 12-byte IV/nonce. BLOB in SQLite. */
    @Column(name = "iv", nullable = false)
    private byte[] iv;

    /** SHA-256 of the ORIGINAL plaintext, hex-encoded (64 chars). */
    @Column(name = "sha256_hash", nullable = false, length = 64)
    private String sha256Hash;

    @Column(name = "file_size")
    private long fileSize;

    @Column(name = "uploaded_at", nullable = false)
    private LocalDateTime uploadedAt;

    /** Every file belongs to exactly one user; ownership enforced in Phase 4. */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User owner;

    /** Required by JPA. */
    protected StoredFile() {}

    public StoredFile(String originalFilename, String storedFilename,
                      byte[] encryptedAesKey, byte[] iv,
                      String sha256Hash, long fileSize, User owner) {
        this.originalFilename = originalFilename;
        this.storedFilename = storedFilename;
        this.encryptedAesKey = encryptedAesKey;
        this.iv = iv;
        this.sha256Hash = sha256Hash;
        this.fileSize = fileSize;
        this.owner = owner;
        this.uploadedAt = LocalDateTime.now();
    }

    @PrePersist
    void onCreate() {
        if (uploadedAt == null) {
            uploadedAt = LocalDateTime.now();
        }
    }

    public Long getId() { return id; }
    public String getOriginalFilename() { return originalFilename; }
    public void setOriginalFilename(String v) { this.originalFilename = v; }
    public String getStoredFilename() { return storedFilename; }
    public void setStoredFilename(String v) { this.storedFilename = v; }
    public byte[] getEncryptedAesKey() { return encryptedAesKey; }
    public void setEncryptedAesKey(byte[] v) { this.encryptedAesKey = v; }
    public byte[] getIv() { return iv; }
    public void setIv(byte[] v) { this.iv = v; }
    public String getSha256Hash() { return sha256Hash; }
    public void setSha256Hash(String v) { this.sha256Hash = v; }
    public long getFileSize() { return fileSize; }
    public void setFileSize(long v) { this.fileSize = v; }
    public LocalDateTime getUploadedAt() { return uploadedAt; }
    public User getOwner() { return owner; }
    public void setOwner(User owner) { this.owner = owner; }
}
