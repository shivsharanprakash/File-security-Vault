package com.vault.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Disk / key / crypto I/O failure — mapped to 500 without internal paths. */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class FileStorageException extends RuntimeException {
    public FileStorageException(String m) { super(m); }
    public FileStorageException(String m, Throwable c) { super(m, c); }
}
