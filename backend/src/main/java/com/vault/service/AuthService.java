package com.vault.service;

import com.vault.dto.RegisterRequest;
import com.vault.entity.User;
import com.vault.exception.DuplicateUsernameException;
import com.vault.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Registration hashes with BCrypt; login delegates to Spring's
 * AuthenticationManager (DAO provider + BCrypt match) — no manual
 * plaintext comparison anywhere.
 */
@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public User register(RegisterRequest req) {
        String username = req.getUsername().trim();
        if (users.existsByUsername(username)) {
            throw new DuplicateUsernameException(username);
        }
        // Plain password only lives in this call frame; only the hash is persisted.
        String hash = passwordEncoder.encode(req.getPassword());
        return users.save(new User(username, hash));
    }

    public Authentication login(String username, String password) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
    }
}
