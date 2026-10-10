# Secure File Vault — INS Viva Q&A

Short, technically correct answers. Expand in your own words.

1. **What is encryption?** Reversible transform with a key: plaintext -> ciphertext -> plaintext. Protects confidentiality.
2. **Symmetric encryption?** Same key encrypts and decrypts (AES). Fast, but key must be shared/stored safely.
3. **Asymmetric encryption?** Public key encrypts, private key decrypts (RSA). Solves key distribution but is slow and size-limited.
4. **Why AES instead of RSA for the file?** RSA-2048-OAEP fits ~190 bytes; files are KB-MB and RSA is ~1000x slower. AES-GCM streams bulk data fast.
5. **Why RSA only for the AES key?** The 32-byte key fits RSA perfectly; wrapping it lets us store per-file keys safely without a shared master secret in code.
6. **What is hybrid encryption?** Bulk symmetric encryption + asymmetric key wrapping — exactly our flow.
7. **Why AES-256?** 256-bit key, ~2^256 brute-force space; required by the spec, supported by JCA with unlimited-strength policy built into JDK 21.
8. **Why AES-GCM?** Authenticated encryption: confidentiality + 128-bit auth tag that fails closed on any bit-flip. No separate HMAC needed.
9. **What is an IV/nonce?** 12-byte randomizer so identical files encrypt differently; stored alongside the blob (not secret).
10. **Why must a GCM IV not be reused with the same key?** Reuse leaks the keystream XOR and destroys authenticity — catastrophic in GCM. We generate a fresh IV per file with SecureRandom.
11. **What is RSA-OAEP?** Optimal Asymmetric Encryption Padding with SHA-256/MGF1 — randomized, CCA-secure padding. Never textbook or PKCS#1 v1.5 for new work.
12. **What is SHA-256?** 256-bit one-way digest; deterministic, avalanche, preimage-resistant. Ours is hex (64 chars).
13. **Encryption vs hashing?** Encryption is reversible with a key; hashing is one-way, verify-by-recompute.
14. **Confidentiality vs integrity?** Confidentiality = nobody can read (AES+RSA); integrity = nobody altered it undetected (GCM tag + SHA-256).
15. **Authentication vs authorization?** Authentication = who are you (Basic+BCrypt); authorization = may you touch THIS file (`findByIdAndOwner`).
16. **Why BCrypt?** Adaptive salted hash with cost factor; slow by design against brute force. We never store or log plaintext.
17. **Why not store passwords directly?** DB leaks then give away every account; hashes (with per-password salts) don't.
18. **Why Basic Auth?** Zero token code for a 2-day build; trivial in Postman (`Authorization: Basic base64(u:p)`); enough with one backend.
19. **Why Basic needs HTTPS?** Credentials ride every request — HTTP exposes them; TLS encrypts transport. Our README states this.
20. **What happens when the encrypted file is tampered with?** GCM tag check throws -> 409, no bytes returned; SHA-256 is a second independent gate.
21. **Why can user A not access user B's file?** Every query is owner-scoped; no `findById` without owner exists in FileService.
22. **Why is `findByIdAndOwner()` important?** Single choke point for IDOR prevention; guessing an ID yields 404, indistinguishable from missing.
23. **Why is the RSA private key not exposed?** Anyone with it decrypts every AES key. It lives in `keys/` (gitignored), backend-only, never in JSON/logs/DB.
24. **Why are files outside SQLite?** DB holds small metadata; blobs on disk avoid bloat and keep ciphertext opaque to SQL.
25. **What if the RSA key pair changes?** All wrapped AES keys become undecryptable — hence generate-once/reload, proven by the fingerprint test.
26. **Limitations?** Basic-over-HTTP only for localhost; local disk/keys; 10MB cap; in-memory file copies; no KMS, AV scan, sharing, or reset flow.
27. **Production improvements?** HTTPS + stronger auth (sessions/OAuth2), KMS/HSM keys, streaming encryption, object storage, audit logs, rate limits, virus scan.
