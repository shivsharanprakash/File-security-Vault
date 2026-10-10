package com.vault.repository;

import com.vault.entity.StoredFile;
import com.vault.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 2 persistence tests: users, file metadata, and ownership isolation
 * (which Phase 4 authorization will depend on).
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class PersistenceTest {

    @Autowired
    private UserRepository users;

    @Autowired
    private StoredFileRepository files;

    private User saveUser(String username) {
        return users.save(new User(username, "$2a$10$test-hash-placeholder"));
    }

    private StoredFile saveFile(User owner, String storedName) {
        byte[] wrappedKey = new byte[256]; // 2048-bit RSA OAEP output size
        wrappedKey[0] = 0x01;
        byte[] iv = new byte[12];
        iv[0] = 0x02;
        return files.save(new StoredFile(
                "notes.txt", storedName, wrappedKey, iv,
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                11L, owner));
    }

    @Test
    void userGetsIdOnSave() {
        User u = saveUser("alice");
        assertNotNull(u.getId());
        assertNotNull(u.getCreatedAt());
    }

    @Test
    void findByUsernameReturnsStoredHash() {
        saveUser("bob");
        Optional<User> found = users.findByUsername("bob");
        assertTrue(found.isPresent());
        assertEquals("bob", found.get().getUsername());
        assertEquals("$2a$10$test-hash-placeholder", found.get().getPasswordHash());
        assertTrue(users.existsByUsername("bob"));
        assertFalse(users.existsByUsername("nobody"));
    }

    @Test
    void storedFilePersistsWithOwner() {
        User owner = saveUser("carol");
        StoredFile f = saveFile(owner, "uuid-1.enc");

        assertNotNull(f.getId());
        assertNotNull(f.getUploadedAt());
        assertEquals(owner.getId(), f.getOwner().getId());
        assertEquals(256, f.getEncryptedAesKey().length);
        assertEquals(12, f.getIv().length);
        assertEquals(64, f.getSha256Hash().length());
    }

    @Test
    void findByOwnerListsOnlyThatUsersFiles() {
        User dave = saveUser("dave");
        User erin = saveUser("erin");
        saveFile(dave, "dave-1.enc");
        saveFile(dave, "dave-2.enc");
        saveFile(erin, "erin-1.enc");

        List<StoredFile> daves = files.findByOwner(dave);
        assertEquals(2, daves.size());
        assertTrue(daves.stream().allMatch(f -> f.getOwner().getId().equals(dave.getId())));
    }

    @Test
    void findByIdAndOwnerDoesNotLeakOtherUsersFile() {
        User frank = saveUser("frank");
        User grace = saveUser("grace");
        StoredFile franksFile = saveFile(frank, "frank-1.enc");

        // Owner CAN access it
        assertTrue(files.findByIdAndOwner(franksFile.getId(), frank).isPresent());
        // Another user MUST NOT get it back
        assertTrue(files.findByIdAndOwner(franksFile.getId(), grace).isEmpty());
    }
}
