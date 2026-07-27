# Mini Vault

Mini Vault is a local FastAPI service implementing the two goals of the assignment:

1. **Secure Storage (KV Engine)** — JSON secrets are encrypted at rest with AES-256-GCM and can only be accessed by the owner identified by a valid session token.
2. **Encryption/Signing as a Service (Transit Engine)** — named AES and ED25519 keys stay server-side; clients receive ciphertext or signatures, never raw private key material.

## Security architecture

- Master Passphrase -> **Argon2id** -> wrapping key.
- Random 256-bit DEK, wrapped with **AES-256-GCM** and stored in `data/vault_config.json`.
- Process restart always returns to `locked`; the plaintext DEK exists only in runtime memory while unlocked.
- User passphrases use Argon2id; session tokens are CSPRNG-generated and only SHA-256 token hashes are stored.
- Five failed logins lock an account for five minutes. An expired lockout starts a fresh failure window.
- KV records and named key material use AES-256-GCM with contextual AAD.
- Transit signing uses **ED25519**. RAW messages are SHA-256 hashed before signing; DIGEST accepts exactly 32 bytes.
- Authorization is evaluated before key unwrap and before Vault-state checks for foreign resources.
- Audit logs never receive passwords, tokens, plaintext secrets, AES keys, or private keys.

## Windows setup

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
- `GET /v1/kv/entries?path=secret/<email>/<name>`
- `DELETE /v1/kv/entries?path=...`

### Transit Engine

- `POST /v1/transit/keys` — create AES-256-GCM named key.
- `POST /v1/transit/signing-keys` — create ED25519 signing key.
- `GET /v1/transit/keys`
- `POST /v1/transit/keys/{key_name}/revoke`
- `POST /v1/transit/encrypt` — input `plaintext_b64`.
- `POST /v1/transit/decrypt` — output `plaintext_b64`.
- `POST /v1/transit/sign`
- `POST /v1/transit/verify`

Transit ciphertext format:

```text
vault:<key_name>:<base64(nonce || ciphertext || tag)>
```

## Test and grading evidence

Run:

```cmd
python -m pytest -q
python -m compileall -q main.py src tests
```

See:

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

Use `reset_runtime_data_cmd.bat` before recording a clean demo.
