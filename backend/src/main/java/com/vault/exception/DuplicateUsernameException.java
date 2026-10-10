package com.vault.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown on duplicate registration -> mapped to 409 Conflict. */
@ResponseStatus(HttpStatus.CONFLICT)
public class DuplicateUsernameException extends RuntimeException {
    public DuplicateUsernameException(String username) {
        super("username already exists: " + username);
    }
}
