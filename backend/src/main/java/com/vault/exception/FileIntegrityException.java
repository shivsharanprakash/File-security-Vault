package com.vault.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** GCM tag failure or SHA-256 mismatch — mapped to 409. No partial data returned. */
@ResponseStatus(HttpStatus.CONFLICT)
public class FileIntegrityException extends RuntimeException {
    public FileIntegrityException() { super("File integrity verification failed"); }
    public FileIntegrityException(String m) { super(m); }
}
