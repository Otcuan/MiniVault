# Mini Vault

**Demo video: https://www.youtube.com/watch?v=2MmLVmJ9FEM&feature=youtu.be**

A local FastAPI service implementing the two goals of the assignment:

1. **Secure Storage (KV Engine)** — JSON secrets are encrypted at rest with AES-256-GCM and can only be accessed by the owner identified by a valid session token.
2. **Encryption/Signing as a Service (Transit Engine)** — named AES and ED25519 keys stay server-side; clients receive ciphertext or signatures, never raw key material.

## Security architecture

- Master Passphrase → **Argon2id** (random 16-byte salt) → wrapping key.
- Random 256-bit DEK, wrapped with **AES-256-GCM** and stored in `data/vault_config.json`. The plaintext DEK exists only in process memory.
- A process restart always comes back `locked`; there is no persisted state that could unlock it.
- User passphrases use Argon2id and pass a strength policy (`src/core/passphrase.py`). Session tokens are CSPRNG-generated and only their SHA-256 hashes are stored.
- Five failed logins lock an account for five minutes. An expired lockout starts a fresh failure window.
- KV records and named key material use AES-256-GCM with contextual AAD binding owner, path/key name and version.
- Transit signing uses **ED25519**. RAW messages are SHA-256 hashed before signing; DIGEST accepts exactly 32 bytes.
- Authorization is evaluated before key unwrap and before Vault-state checks, so no response reveals whether a foreign path or key exists.
- Audit entries carry identifiers and outcomes only — never passphrases, tokens, plaintext secrets, DEK or key material.

## Setup (Windows)

```cmd
cd /d D:\MiniVault
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
python -m uvicorn main:app --reload
```

Swagger: `http://127.0.0.1:8000/docs`

Configuration is optional — see `.env.example`. Every setting has a secure default, and the Master Passphrase is deliberately **not** configurable: it is entered at init/unlock and never written to disk.

## API summary

### Core

- `GET /health`
- `GET /v1/vault/status`
- `POST /v1/vault/init`
- `POST /v1/vault/unlock`
- `POST /v1/vault/lock`

### Authentication

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/logout`

### KV Engine

- `POST /v1/kv/entries`
- `GET /v1/kv/entries?path=secret/<email>/<name>[&version=N]`
- `GET /v1/kv/entries/versions?path=...`
- `DELETE /v1/kv/entries?path=...`

### Transit Engine

- `POST /v1/transit/keys` — create AES-256-GCM named key.
- `POST /v1/transit/signing-keys` — create ED25519 signing key.
- `GET /v1/transit/keys`
- `POST /v1/transit/keys/{key_name}/rotate`
- `POST /v1/transit/keys/{key_name}/revoke` — permanently deletes the key.
- `POST /v1/transit/encrypt` — input `plaintext_b64`.
- `POST /v1/transit/decrypt` — output `plaintext_b64`.
- `POST /v1/transit/sign`
- `POST /v1/transit/verify`

### Audit log

- `GET /v1/audit/entries` — the caller's own audit trail.
- `GET /v1/audit/verify` — recompute the hash chain.

Transit ciphertext format:

```text
vault:<key_name>:<base64(nonce || ciphertext || tag)>          # key version 1
vault:v<N>:<key_name>:<base64(nonce || ciphertext || tag)>     # after rotation
```

## Optional features implemented (section IV)

| Feature | Credit | Where |
|---|---:|---|
| Key rotation for Transit (versioned named keys, old ciphertext still decrypts) | +0.4 | `src/transit/`, `tests/test_transit_rotation.py` |
| KV versioning (history of overwrites) | +0.3 | `src/kv/`, `tests/test_kv_versioning.py` |
| Tamper-evident audit log (hash-chained) | +0.3 | `src/audit/`, `tests/test_audit_chain.py` |

Total: **1.0**, the cap for section IV.

## Design decisions

Choices the assignment leaves to the group, or where the implementation goes beyond the minimum:

- **Duplicate `key_name` → rejected, not overwritten.** Section 2.1 allows either. Creating a key over an existing name would destroy the material that already-issued ciphertext depends on, silently turning every stored ciphertext into undecryptable data. `POST /v1/transit/keys` therefore returns `409 KEY_ALREADY_EXISTS`, and rotation is the supported way to move to fresh material under the same name.
- **`revoke_key` performs a hard delete.** Section 2.1 asks for permanent deletion, so the row and every version of its wrapped material are removed (`ON DELETE CASCADE`), not flagged. A revoked key then answers exactly like a key that never existed, which also avoids confirming that the name was once real.
- **ED25519 signs `SHA-256(message)`, not the message.** Section 2.4 specifies that RAW hashes with SHA-256 first, and this keeps RAW and DIGEST symmetric. Note that this is a pre-hash construction: a standard external Ed25519 verifier fed the raw message will not validate the signature — verification must go through `/v1/transit/verify`, which applies the same digest step.
- **Ciphertext framing stays byte-compatible with section 2.2.** Un-rotated keys emit exactly `vault:<key_name>:<b64>`. The `v<N>` segment only appears once a key has been rotated, and the legacy 3-part form is always accepted on input as version 1.
- **The version is inside the AEAD associated data.** For both KV and Transit. Without it, someone with database write access could roll a secret back by copying an old version's ciphertext over the current one; with it, the moved blob fails tag verification.
- **The audit head hash is stored outside `audit_logs`.** A chain alone detects edits, deletions and reordering, but not truncation of the newest entries — deleting the tail leaves a valid prefix. Keeping the head in `schema_metadata` closes that gap.
- **Argon2 cost parameters are configurable.** Production defaults are in `.env.example`; the test suite lowers only the cost (never the algorithm) so the suite runs in seconds.

## Test and grading evidence

```cmd
python -m pytest -q
python -m compileall -q main.py src tests
python -m coverage run --source=src,main -m pytest -q
python -m coverage report -m
```

Sample evidence files for section VI are generated by driving the real API:

```cmd
python -m scripts.generate_samples
```

This writes `data/samples/` (encrypted KV rows, Transit ciphertext before and after rotation, signatures, wrapped DEK, audit chain, and the SQLite database) and fails loudly if any plaintext marker is found in the database.

See also:

- `tests/test_matrix.md`
- `docs/REQUIREMENT_TRACEABILITY.md`
- `docs/REPORT.md`
- `docs/DEMO_SCRIPT.md`
- `docs/REFLECTION.md`
- `docs/TEST_RESULTS.md`

## Runtime files

The following must not be committed or submitted with real secrets:

- `data/mini_vault.db`
- `data/vault_config.json`
- `.env`

Use `reset_runtime_data_cmd.bat` before recording a clean demo. The files under `data/samples/` are generated demo data and contain no real secrets.
