package com.vault.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vault.dto.LoginRequest;
import com.vault.dto.RegisterRequest;
import com.vault.entity.User;
import com.vault.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Phase 3 auth tests: register/login status codes, BCrypt storage,
 * and that non-auth routes demand credentials.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private RegisterRequest reg(String u, String p) {
        RegisterRequest r = new RegisterRequest();
        r.setUsername(u);
        r.setPassword(p);
        return r;
    }

    @Test
    void registerReturns201AndStoresBcryptHash() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(reg("authuser1", "StrongPass123"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("authuser1"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        User saved = users.findByUsername("authuser1").orElseThrow();
        assertNotEquals("StrongPass123", saved.getPasswordHash());
        assertTrue(saved.getPasswordHash().startsWith("$2a$")
                || saved.getPasswordHash().startsWith("$2b$"));
        assertTrue(passwordEncoder.matches("StrongPass123", saved.getPasswordHash()));
    }

    @Test
    void duplicateRegisterReturns409() throws Exception {
        String body = json.writeValueAsString(reg("authuser2", "StrongPass123"));
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void invalidRegisterReturns400() throws Exception {
        RegisterRequest bad = new RegisterRequest(); // blank username + short password
        bad.setUsername("");
        bad.setPassword("short");
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(bad)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginSuccessAndFailure() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(reg("authuser3", "StrongPass123"))))
                .andExpect(status().isCreated());

        LoginRequest ok = new LoginRequest();
        ok.setUsername("authuser3");
        ok.setPassword("StrongPass123");
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(ok)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("authuser3"));

        LoginRequest bad = new LoginRequest();
        bad.setUsername("authuser3");
        bad.setPassword("WrongPass999");
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(bad)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedRouteRequiresAuth() throws Exception {
        mvc.perform(get("/api/files"))
                .andExpect(status().isUnauthorized());

        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(reg("authuser4", "StrongPass123"))))
                .andExpect(status().isCreated());

        // With valid Basic credentials the file list is reachable (200, empty list).
        mvc.perform(get("/api/files").with(httpBasic("authuser4", "StrongPass123")))
                .andExpect(status().isOk());
    }

    @Test
    void bcryptMatchesOnlyCorrectPassword() {
        String hash = passwordEncoder.encode("CheckMe123");
        assertTrue(passwordEncoder.matches("CheckMe123", hash));
        assertFalse(passwordEncoder.matches("WrongOne99", hash));
    }
}
