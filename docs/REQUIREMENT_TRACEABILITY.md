# Requirement Traceability

## Section III — mandatory (8.5 points of code)

| Rubric | Points | Implementation evidence | Test evidence |
|---|---:|---|---|
| 0.1 Init & Unlock | 1.00 | `src/core/vault.py`, `src/core/kdf.py`, `src/storage/config_store.py` | `tests/test_core.py` |
| 0.2 User Authentication | 1.00 | `src/auth/*`, `src/core/passphrase.py`, `src/api/auth_*` | `tests/test_auth.py`, `tests/test_passphrase_policy.py` |
| 1.1 KV Encrypted-at-Rest | 1.25 | `src/kv/service.py`, `src/kv/repository.py` | `tests/test_kv.py` |
| 1.2 KV Access Control | 1.00 | `src/auth/dependencies.py`, `src/kv/paths.py`, `KvService._authorize` | cross-user tests in `tests/test_kv.py` |
| 2.1 Transit Key Management | 1.00 | `src/transit/repository.py`, `TransitService.create_key` / `list_keys` / `delete_key` | `tests/test_transit_keys.py` |
| 2.2 Transit Encrypt/Decrypt | 1.25 | `src/transit/ciphertext.py`, `TransitService.encrypt` / `decrypt` | `tests/test_transit_crypto.py`, `tests/test_transit_ciphertext.py` |
| 2.3 Transit Access Control | 1.00 | `TransitService._owned_key()` before `_unwrap()` and before Vault-state checks | cross-user tests in `tests/test_transit_crypto.py`, `tests/test_transit_keys.py` |
| 2.4 Sign & Verify | 1.00 | ED25519 RAW/DIGEST in `src/transit/service.py` | `tests/test_sign_verify.py` |
| Report/README/task assignment | 0.75 | `README.md`, `docs/REPORT.md` | manual review |
| Product Demo | 0.75 | `docs/DEMO_SCRIPT.md` | record 3–5 minute video |

## Section IV — optional (capped at 1.0)

| Feature | Credit | Implementation evidence | Test evidence |
|---|---:|---|---|
| Key rotation for Transit | +0.4 | `named_key_versions` table, `TransitService.rotate_key`, versioned ciphertext framing | `tests/test_transit_rotation.py` |
| KV versioning | +0.3 | `kv_versions` table, `KvRepository.append_version`, `?version=` reads | `tests/test_kv_versioning.py` |
| Tamper-evident audit log | +0.3 | `src/audit/chain.py`, `src/audit/repository.py`, `GET /v1/audit/verify` | `tests/test_audit_chain.py` |

## Section VI — submission artefacts

| Requirement | Where |
|---|---|
| Full source organised into modules + README | `src/`, `main.py`, `README.md` |
| Encrypted KV data file | `data/samples/kv_encrypted_sample.json`, `data/samples/mini_vault_sample.db` |
| Sample ciphertext from Transit | `data/samples/transit_ciphertext_sample.json` |
| Wrapped DEK / KDF parameters | `data/samples/vault_config_sample.json` |
| Audit chain evidence | `data/samples/audit_chain_sample.json` |
| Environment template | `.env.example` |
| Report (team, IDs, architecture, screenshots) | `docs/REPORT.md`, `docs/Report_*.pdf` — **student IDs and figures still to be filled in** |
| Demo video | to be recorded, link to be added to `README.md` |

## Assignment success criteria

- Data persisted on disk is ciphertext, not plaintext — including superseded KV versions and every key version.
- Only the rightful owner can read/write KV data and use named keys.
- Encryption and signing key material never leaves the server.
