# Mini Vault Requirement/Test Matrix

## Section III — mandatory

| Rubric | Requirement | Automated evidence | Status |
|---|---|---|---|
| 0.1 | Init/Unlock, Argon2id, wrapped DEK, restart locked | `tests/test_core.py` | done |
| 0.2 | Register/Login, Argon2id, passphrase strength, session expiry, 5 failures / 5 minutes | `tests/test_auth.py`, `tests/test_passphrase_policy.py` | done |
| 1.1 | KV AEAD encrypted-at-rest, tamper detection, no plaintext | `tests/test_kv.py` | done |
| 1.2 | Token ownership for `secret/<email>/...` | `tests/test_kv.py` | done |
| 2.1 | Named AES/signing keys, encrypted key material, permanent delete, no key export | `tests/test_transit_keys.py` | done |
| 2.2 | `vault:<key>:<base64>` encrypt/decrypt and tamper rejection | `tests/test_transit_crypto.py`, `tests/test_transit_ciphertext.py` | done |
| 2.3 | Named-key access control before unwrap and before Vault state | `tests/test_transit_crypto.py`, `tests/test_transit_keys.py` | done |
| 2.4 | ED25519 RAW/DIGEST sign/verify, tamper and cross-key tests | `tests/test_sign_verify.py` | done |
| E2E | Full flow | `tests/test_end_to_end.py` | done |

## Section IV — optional (1.0 total)

| Feature | Requirement | Automated evidence | Status |
|---|---|---|---|
| Key rotation (+0.4) | Versioned named keys, old ciphertext still decryptable | `tests/test_transit_rotation.py` | done |
| KV versioning (+0.3) | History of overwrites retained and readable | `tests/test_kv_versioning.py` | done |
| Audit chain (+0.3) | Hash-chained log, detects tampering | `tests/test_audit_chain.py` | done |

## Attacks the suite actively performs

Each of these mutates state behind the API's back and asserts the system refuses:

| Attack | Test |
|---|---|
| Flip a byte of a KV ciphertext on disk | `test_tampered_record_detected` |
| Copy an old KV version over the current one (rollback) | `test_rollback_by_copying_an_old_version_is_detected` |
| Flip a byte of the wrapped DEK in the config | `test_tampered_wrapped_dek_rejected` |
| Flip a byte of a Transit ciphertext | `test_tampered_ciphertext_detected` |
| Relabel a v1 ciphertext as v2 after rotation | `test_version_is_bound_into_the_associated_data` |
| Forge a ciphertext naming a nonexistent key version | `test_ciphertext_naming_a_missing_version_is_rejected` |
| Alter a message after signing | `test_tampered_message_returns_false` |
| Verify a signature against a different named key | `test_cross_key_signature_returns_false` |
| Read/write/delete another user's KV path | `test_cross_user_read_write_delete_denied` |
| Use another user's named key | `test_cross_user_cannot_decrypt`, `test_cross_user_cannot_sign_with_foreign_key` |
| Reach a path check with no token | `test_missing_and_expired_token_unauthenticated` |
| Edit, delete, reorder or truncate the audit log | `tests/test_audit_chain.py` |
