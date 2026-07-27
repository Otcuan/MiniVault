# Code Explanation

- `src/core`: Argon2id, DEK wrapping, runtime lock/unlock.
- `src/auth`: Argon2 user hashes, session token hashing/expiry, 5-minute lockout.
- `src/kv`: owner-path authorization and AES-GCM encrypted-at-rest JSON.
- `src/transit`: named AES/ED25519 key management, encrypt/decrypt and sign/verify.
- `src/storage`: atomic JSON config and SQLite schema.
- `src/api`: FastAPI routes and Pydantic contracts.
- `tests`: rubric, negative, tamper, cross-user, and end-to-end evidence.

Key rule: DEK, named AES keys, private signing keys, passwords, tokens, and plaintext secrets are never returned by an API or sent to audit logs.
