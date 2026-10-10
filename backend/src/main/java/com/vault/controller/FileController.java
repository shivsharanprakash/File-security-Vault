package com.vault.controller;

import com.vault.dto.FileInfoResponse;
import com.vault.entity.StoredFile;
import com.vault.service.FileService;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * POST /api/files/upload | GET /api/files
 * GET /api/files/{id}/download | DELETE /api/files/{id}
 * All ownership from the authenticated principal (findByIdAndOwner).
 */
@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<FileInfoResponse> upload(@RequestParam("file") MultipartFile file) {
        StoredFile saved = fileService.upload(file);
        return ResponseEntity.status(201).body(FileInfoResponse.from(saved));
    }

    @GetMapping
    public List<FileInfoResponse> list() {
        return fileService.listMine().stream().map(FileInfoResponse::from).toList();
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<Resource> download(@PathVariable long id) {
        FileService.DecryptedFile d = fileService.download(id);
        ContentDisposition cd = ContentDisposition.attachment()
                .filename(d.originalFilename(), StandardCharsets.UTF_8).build();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, cd.toString())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(d.content().length)
                .body(new ByteArrayResource(d.content()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable long id) {
        fileService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
