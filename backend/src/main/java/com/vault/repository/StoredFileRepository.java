package com.vault.repository;

import com.vault.entity.StoredFile;
import com.vault.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface StoredFileRepository extends JpaRepository<StoredFile, Long> {
    /** All files owned by one user (dashboard list). */
    List<StoredFile> findByOwner(User owner);

    /** Ownership-scoped lookup: prevents user A reading user B's file. */
    Optional<StoredFile> findByIdAndOwner(Long id, User owner);
}
