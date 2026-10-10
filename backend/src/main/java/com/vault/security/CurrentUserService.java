package com.vault.security;

import com.vault.entity.User;
import com.vault.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Resolves the currently authenticated DB user.
 * Phase 4 file endpoints will use this for ownership checks.
 */
@Service
public class CurrentUserService {

    private final UserRepository users;

    public CurrentUserService(UserRepository users) {
        this.users = users;
    }

    /** Username from the SecurityContext (set by Basic Auth or login). */
    public String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || "anonymousUser".equals(String.valueOf(auth.getPrincipal()))) {
            throw new UsernameNotFoundException("not authenticated");
        }
        return auth.getName();
    }

    public User currentUser() {
        return users.findByUsername(currentUsername())
                .orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }
}
