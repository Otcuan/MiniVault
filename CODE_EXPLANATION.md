# Code Explanation

## Modules

- `src/core`: Argon2id KDF, DEK wrapping, runtime lock/unlock state, passphrase strength policy, environment settings.
- `src/auth`: Argon2id user hashes, session token hashing and expiry, five-failure / five-minute lockout.
- `src/kv`: owner-path authorization and AES-GCM encrypted-at-rest JSON, with version history.
- `src/transit`: named AES/ED25519 key management, key rotation, encrypt/decrypt and sign/verify.
- `src/audit`: hash-chained audit log and chain verification.
- `src/storage`: atomic JSON config, SQLite schema and transaction helpers.
- `src/api`: FastAPI routes and Pydantic contracts.
- `scripts/generate_samples.py`: produces the section VI evidence files by driving the real API.
- `tests`: rubric, negative, tamper, cross-user, versioning, rotation, chain and end-to-end evidence.

## Invariants the code is built around

1. **Key material never leaves the process.** The DEK, named AES keys and ED25519 private keys are unwrapped only inside a service method, are never placed in a response model, and never reach the audit log.
2. **Identity comes from the session token, never from the request body.** Every KV and Transit route depends on `get_current_user`.
3. **Authorization runs before cryptography and before the Vault-state check.** A caller cannot use timing or error codes to learn whether a foreign path or key exists.
4. **Everything persisted is authenticated.** Every ciphertext on disk carries a GCM tag with associated data binding it to its owner, its name and its version, so a row cannot be edited, moved or rolled back undetected.
5. **Failures are refusals, not partial answers.** A tag mismatch returns an error; it never returns data that "might be right, might be wrong".

## Transaction helpers

`Database.connection()` is the ordinary path. `Database.exclusive_connection()` runs `BEGIN IMMEDIATE` and is used where a read-then-write must be atomic:

- allocating the next KV or key version, because the version number is bound into the associated data and so must be known before encryption;
- appending an audit entry, because two concurrent writers reading the same predecessor hash would fork the chain.
