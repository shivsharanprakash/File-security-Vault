package com.vault.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Unknown id OR not the caller's file — mapped to 404 to avoid leaking existence. */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class VaultFileNotFoundException extends RuntimeException {
    public VaultFileNotFoundException() { super("File not found"); }
}
