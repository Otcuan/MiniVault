# Test Results

Validation date: 2026-07-27

## Commands

```cmd
python -m compileall -q main.py src tests
python -m pytest -q -W error
python -m coverage run --source=src,main -m pytest -q
python -m coverage report -m
python -m scripts.generate_samples
```

## Results

- Automated tests: **109 passed**.
- Warnings-as-errors run: **passed**.
- Statement coverage of `src` + `main.py`: **95%**.
  (Measured over application code only. An earlier figure of 96% included the
  test files themselves in the denominator, which flatters the number.)
- OpenAPI smoke check: all Core, Authentication, KV, Transit, Sign/Verify and Audit routes registered.
- Sample generation: passes its own no-plaintext assertion over the produced database.

## Coverage emphasis

Mandatory scope (sections 0.1 – 2.4):

- Init, restart-to-locked, wrong passphrase, tampered wrapped DEK, no plaintext DEK on disk.
- Register, duplicate email, passphrase strength, Argon2id hashing, login, token expiry, logout, five-failure lockout and its expiry reset.
- KV round-trip, overwrite, delete, not-found, ciphertext-at-rest, tampered tag, cross-user read/write/delete, audit of denials.
- Named key creation, listing, permanent deletion, encrypted key material, no key export by any endpoint.
- Transit malformed, truncated and tampered ciphertext; wrong key usage; cross-user denial.
- ED25519 RAW and DIGEST sign/verify; altered message; cross-key signature; malformed signature; algorithm mismatch.
- End-to-end assignment flow.

Section IV extras:

- **Key rotation**: version allocation, fresh material per rotation, old ciphertext still decrypts, version-segment framing, missing version rejected, version bound into AAD, signing-key rotation, pinned verification, cross-user and locked-vault denial.
- **KV versioning**: version numbering, historical reads, version listing, unknown and invalid versions, rollback-by-copy detection, delete removes all versions, cross-user denial, history stays ciphertext.
- **Audit chain**: clean verification, edit / delete / reorder / truncate detection, per-field hash sensitivity, caller-scoped listing, authentication required, no secrets in the log.
