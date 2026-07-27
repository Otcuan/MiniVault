# Test Results

Validation date: 2026-07-27

## Commands

```cmd
python -m compileall -q main.py src tests
python -m pytest -q -W error
python -m coverage run -m pytest -q
python -m coverage report -m
```

## Results

- Automated tests: **58 passed**.
- Warnings-as-errors run: **passed**.
- Statement coverage: **96%**.
- OpenAPI smoke check: all Core, Authentication, KV, Transit, and Sign/Verify routes registered.

## Coverage emphasis

- Positive and negative flows.
- Restart and lock-state behavior.
- Password/token storage protections.
- Five-failure/five-minute lockout, including expiry reset.
- KV ciphertext-at-rest and tamper detection.
- Cross-user KV and named-key denial.
- Named key creation/list/revoke and encrypted key material.
- Transit malformed/truncated/tampered ciphertext.
- ED25519 RAW/DIGEST signing and verification.
- Altered message, cross-key signature, malformed signature.
- End-to-end assignment flow.
