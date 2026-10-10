package com.vault.controller;

import com.vault.dto.AuthResponse;
import com.vault.dto.LoginRequest;
import com.vault.dto.RegisterRequest;
import com.vault.entity.User;
import com.vault.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * POST /api/auth/register -> 201 (409 on duplicate, 400 on invalid input)
 * POST /api/auth/login    -> 200 (401 on bad credentials via handler)
 * No password/hash is ever returned.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest req) {
        User saved = authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new AuthResponse("registered", saved.getUsername()));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req) {
        Authentication auth = authService.login(req.getUsername(), req.getPassword());
        return ResponseEntity.ok(new AuthResponse("authenticated", auth.getName()));
    }
}
