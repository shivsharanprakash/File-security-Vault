# Secure File Vault

**Java 21 · Spring Boot 3.2.5 · React + Vite · AES-256-GCM · RSA-2048-OAEP · SHA-256 · BCrypt · SQLite**

Authenticated users upload files. Each file gets a fresh random AES-256 key
(AES-GCM encrypts the file), the AES key is wrapped with RSA-2048-OAEP, and a
SHA-256 digest of the original file is stored. Downloads unwrap the key,
decrypt, re-hash, and reject on any mismatch.

## Architecture

```
React (Vite, :5173)  --Basic Auth-->  Spring Boot (:8080)
                                              |
                       +----------------------+----------------------+
                       |                      |                      |
                 crypto/ (JCA)        entity+repository (SQLite)  security (BCrypt)
                 AesGcmUtil           users / stored_files        HTTP Basic
                 RsaOaepUtil          blobs on disk in storage/   RsaKeyStoreService
                 HashUtil             keys/*.der (gitignored)
```

## Security flow

Upload: `file -> SHA-256 -> fresh AES key+IV -> AES-GCM -> storage/<uuid>.enc -> RSA-OAEP(key) -> SQLite row`
Download: `findByIdAndOwner -> read blob -> RSA unwrap -> AES-GCM decrypt (tag check) -> SHA-256 compare -> bytes or 409`

Why hybrid: AES is fast for large files; RSA is slow and size-limited, so it
only protects the 32-byte key. GCM adds authentication (tamper => tag failure).
SHA-256 gives an independent integrity comparison. `findByIdAndOwner` keeps
user A from ever reaching user B's file (404 either way, no existence leak).
Encrypted blobs use server UUID names; the original filename is metadata only.

## API

| Method | Path | Auth | Success |
|---|---|---|---|
| POST | /api/auth/register `{username,password}` | no | 201 (409 duplicate, 400 invalid) |
| POST | /api/auth/login `{username,password}` | no | 200 (401 bad creds) |
| POST | /api/files/upload (multipart `file`) | Basic | 201 FileInfo |
| GET | /api/files | Basic | 200 own files only |
| GET | /api/files/{id}/download | Basic+owner | 200 bytes / 404 / 409 integrity |
| DELETE | /api/files/{id} | Basic+owner | 204 / 404 |

Errors: `{status, message}` — never stack traces, keys, hashes of passwords,
or internal paths. List/download DTOs exclude `encryptedAesKey`/IV/ciphertext.

## Setup

Backend:
```powershell
cd backend
mvn clean test
mvn spring-boot:run   # :8080, creates data/, storage/, keys/
```

Frontend:
```powershell
cd frontend
npm install
npm run dev           # :5173
```

Demo: register `prakash` / `StrongPassword123` -> upload `sample.pdf` ->
`storage/` holds `<uuid>.enc` (not plaintext) -> download matches original.

## Tamper demo (viva highlight)

1. Upload, download once (works).
2. Flip one byte in `storage/<uuid>.enc` (e.g. hex editor).
3. Download again -> `409 {"status":409,"message":"File integrity verification failed"}`.
   AES-GCM rejects the tag before any SHA-256 comparison; nothing partial is returned.

## Configuration

- `app.storage.dir` (default `./storage`), `app.keys.dir` (default `./keys`).
- Keystore password: `VAULT_KEYSTORE_PASSWORD` env var (dev fallback only).
- 10MB multipart cap. Memory note: upload/download hold one file copy in memory
  (bounded by the cap) because the verified byte-array `AesGcmUtil` was kept
  intentionally; streaming is future work, not a silent regression risk.

## Limitations (honest)

- HTTP Basic must run over HTTPS in production (credentials per request).
- Local disk storage, local RSA key files — no KMS/HSM, no distribution.
- No antivirus/content scan, no sharing, no password reset, no refresh tokens.
- Dev-fallback keystore password; set the env var for anything beyond localhost.
- No "military-grade / 100% secure" claims — this is a teaching build.
