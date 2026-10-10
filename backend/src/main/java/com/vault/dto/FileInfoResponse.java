package com.vault.dto;

import com.vault.entity.StoredFile;
import java.time.LocalDateTime;

/** Safe listing payload — never includes keys, IV, or ciphertext. */
public class FileInfoResponse {
    private Long id;
    private String originalFilename;
    private long fileSize;
    private LocalDateTime uploadedAt;
    private String sha256Hash;
    private String integrity = "Protected";

    public FileInfoResponse() {}

    public static FileInfoResponse from(StoredFile f) {
        FileInfoResponse r = new FileInfoResponse();
        r.id = f.getId();
        r.originalFilename = f.getOriginalFilename();
        r.fileSize = f.getFileSize();
        r.uploadedAt = f.getUploadedAt();
        r.sha256Hash = f.getSha256Hash();
        return r;
    }

    public Long getId() { return id; }
    public String getOriginalFilename() { return originalFilename; }
    public long getFileSize() { return fileSize; }
    public LocalDateTime getUploadedAt() { return uploadedAt; }
    public String getSha256Hash() { return sha256Hash; }
    public String getIntegrity() { return integrity; }
}
