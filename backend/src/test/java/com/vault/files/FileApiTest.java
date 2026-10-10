package com.vault.files;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vault.entity.StoredFile;
import com.vault.entity.User;
import com.vault.repository.StoredFileRepository;
import com.vault.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Phase 4: upload/list/download/delete + isolation + tamper detection. */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class FileApiTest {

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper json;
    @Autowired private UserRepository users;
    @Autowired private StoredFileRepository files;
    @Autowired private PasswordEncoder encoder;

    @Value("${app.storage.dir:./storage}")
    private String storageDir;

    @BeforeEach
    void seedUsers() {
        if (!users.existsByUsername("fileowner")) {
            users.save(new User("fileowner", encoder.encode("OwnerPass123")));
        }
        if (!users.existsByUsername("fileother")) {
            users.save(new User("fileother", encoder.encode("OtherPass123")));
        }
    }

    private long upload(String user, String pass, byte[] content, String name) throws Exception {
        MockMultipartFile part = new MockMultipartFile("file", name,
                MediaType.TEXT_PLAIN_VALUE, content);
        String res = mvc.perform(multipart("/api/files/upload").file(part)
                        .with(httpBasic(user, pass)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.originalFilename").value(name))
                .andExpect(jsonPath("$.encryptedAesKey").doesNotExist())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(res).get("id").asLong();
    }

    @Test
    void uploadEncryptsListDownloadsDeletes() throws Exception {
        byte[] original = "INS vault secret notes".getBytes();
        long id = upload("fileowner", "OwnerPass123", original, "notes.txt");

        StoredFile meta = files.findById(id).orElseThrow();
        Path blob = Path.of(storageDir, meta.getStoredFilename());
        assertTrue(Files.exists(blob), "encrypted blob must exist on disk");
        assertFalse(Arrays.equals(original, Files.readAllBytes(blob)),
                "stored bytes must NOT be plaintext");
        assertNotEquals(meta.getOriginalFilename(), meta.getStoredFilename());
        assertEquals(64, meta.getSha256Hash().length());

        String list = mvc.perform(get("/api/files").with(httpBasic("fileowner", "OwnerPass123")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(list.contains("notes.txt"));

        byte[] downloaded = mvc.perform(get("/api/files/" + id + "/download")
                        .with(httpBasic("fileowner", "OwnerPass123")))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("notes.txt")))
                .andReturn().getResponse().getContentAsByteArray();
        assertArrayEquals(original, downloaded);

        mvc.perform(delete("/api/files/" + id).with(httpBasic("fileowner", "OwnerPass123")))
                .andExpect(status().isNoContent());
        assertTrue(files.findById(id).isEmpty());
        assertFalse(Files.exists(blob));
    }

    @Test
    void crossUserAccessDeniedAndListsIsolated() throws Exception {
        long id = upload("fileowner", "OwnerPass123", "owner secret".getBytes(), "o.txt");
        upload("fileother", "OtherPass123", "other secret".getBytes(), "t.txt");

        mvc.perform(get("/api/files/" + id + "/download")
                        .with(httpBasic("fileother", "OtherPass123")))
                .andExpect(status().isNotFound());
        mvc.perform(delete("/api/files/" + id)
                        .with(httpBasic("fileother", "OtherPass123")))
                .andExpect(status().isNotFound());

        String otherList = mvc.perform(get("/api/files")
                        .with(httpBasic("fileother", "OtherPass123")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(otherList.contains("t.txt"));
        assertFalse(otherList.contains("o.txt"));
    }

    @Test
    void tamperedBlobFailsIntegrity() throws Exception {
        byte[] original = "tamper demo content".getBytes();
        long id = upload("fileowner", "OwnerPass123", original, "t.txt");

        StoredFile meta = files.findById(id).orElseThrow();
        Path blob = Path.of(storageDir, meta.getStoredFilename());
        byte[] cipher = Files.readAllBytes(blob);
        cipher[cipher.length / 2] ^= 0x01;
        Files.write(blob, cipher);

        mvc.perform(get("/api/files/" + id + "/download")
                        .with(httpBasic("fileowner", "OwnerPass123")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("File integrity verification failed"));
    }

    @Test
    void unauthenticatedUploadRejected() throws Exception {
        MockMultipartFile part = new MockMultipartFile("file", "x.txt",
                MediaType.TEXT_PLAIN_VALUE, "x".getBytes());
        mvc.perform(multipart("/api/files/upload").file(part))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void errorEnvelopeShape() throws Exception {
        String res = mvc.perform(get("/api/files/999999/download")
                        .with(httpBasic("fileowner", "OwnerPass123")))
                .andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
        JsonNode n = json.readTree(res);
        assertEquals(404, n.get("status").asInt());
        assertNotNull(n.get("message").asText());
    }
}
