# Requirement Traceability

| Rubric | Points | Implementation evidence | Test evidence |
|---|---:|---|---|
| 0.1 Init & Unlock | 1.00 | `src/core/*`, `src/storage/config_store.py` | `tests/test_core.py` |
| 0.2 User Authentication | 1.00 | `src/auth/*`, `src/api/auth_*` | `tests/test_auth.py` |
| 1.1 KV Encrypted-at-Rest | 1.25 | `src/kv/service.py`, `src/kv/repository.py` | `tests/test_kv.py` |
| 1.2 KV Access Control | 1.00 | `src/auth/dependencies.py`, `src/kv/paths.py` | cross-user tests in `tests/test_kv.py` |
| 2.1 Transit Key Management | 1.00 | `src/transit/repository.py`, key creation/list/revoke | `tests/test_transit_keys.py` |
| 2.2 Transit Encrypt/Decrypt | 1.25 | `src/transit/ciphertext.py`, `TransitService.encrypt/decrypt` | `tests/test_transit_crypto.py` |
| 2.3 Transit Access Control | 1.00 | `_owned_key()` before `_unwrap()`/Vault checks | cross-user tests |
| 2.4 Sign & Verify | 1.00 | ED25519 RAW/DIGEST in `src/transit/service.py` | `tests/test_sign_verify.py` |
| Report/README/task assignment | 0.75 | `README.md`, `docs/REPORT.md` | manual review |
| Product Demo | 0.75 | `docs/DEMO_SCRIPT.md` | record 3–5 minute video |

## Assignment success criteria

- Data persisted on disk is ciphertext, not plaintext.
- Only the rightful owner can read/write KV data and use named keys.
- Encryption and signing key material never leaves the server.
