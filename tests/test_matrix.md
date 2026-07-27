# Mini Vault Requirement/Test Matrix

| Rubric | Requirement | Automated evidence | Status |
|---|---|---|---|
| 0.1 | Init/Unlock, Argon2id, wrapped DEK, restart locked | `tests/test_core.py` | done |
| 0.2 | Register/Login, Argon2, session expiry, 5 failures/5 minutes | `tests/test_auth.py` | done |
| 1.1 | KV AEAD encrypted-at-rest, tamper detection, no plaintext | `tests/test_kv.py` | done |
| 1.2 | Token ownership for `secret/<email>/...` | `tests/test_kv.py` | done |
| 2.1 | Named AES/signing keys; encrypted key material; no key export | `tests/test_transit_keys.py` | done |
| 2.2 | `vault:<key>:<base64>` encrypt/decrypt and tamper rejection | `tests/test_transit_crypto.py` | done |
| 2.3 | Named-key access control before unwrap/Vault state | `tests/test_transit_crypto.py`, `tests/test_transit_keys.py` | done |
| 2.4 | ED25519 RAW/DIGEST sign/verify, tamper/cross-key tests | `tests/test_sign_verify.py` | done |
| E2E | Full flow | `tests/test_end_to_end.py` | done |
