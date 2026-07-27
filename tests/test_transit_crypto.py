import base64

from fastapi.testclient import TestClient

from tests.conftest import b64


def create_key(client: TestClient, headers, name="data-key") -> None:
    assert client.post("/v1/transit/keys", json={"key_name": name}, headers=headers).status_code == 201


def test_encrypt_decrypt_roundtrip_binary(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers)
    plaintext = bytes(range(256))
    encrypted = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "data-key", "plaintext_b64": b64(plaintext)},
        headers=alice_headers,
    )
    assert encrypted.status_code == 200
    token = encrypted.json()["ciphertext"]
    assert token.startswith("vault:data-key:")
    decrypted = unlocked_client.post(
        "/v1/transit/decrypt", json={"ciphertext": token}, headers=alice_headers
    )
    assert base64.b64decode(decrypted.json()["plaintext_b64"]) == plaintext


def test_malformed_and_truncated_ciphertext_rejected(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers)
    for token in ("bad", "vault:data-key:not-base64!", "vault:data-key:AAAA"):
        response = unlocked_client.post("/v1/transit/decrypt", json={"ciphertext": token}, headers=alice_headers)
        assert response.status_code == 400
        assert response.json()["error"] == "MALFORMED_CIPHERTEXT"


def test_tampered_ciphertext_detected(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers)
    token = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "data-key", "plaintext_b64": b64("secret")},
        headers=alice_headers,
    ).json()["ciphertext"]
    prefix, key_name, payload = token.split(":", 2)
    index = len(payload) // 2
    payload = payload[:index] + ("A" if payload[index] != "A" else "B") + payload[index + 1 :]
    response = unlocked_client.post(
        "/v1/transit/decrypt",
        json={"ciphertext": f"{prefix}:{key_name}:{payload}"},
        headers=alice_headers,
    )
    assert response.status_code == 409
    assert response.json()["error"] == "TAMPER_DETECTED"


def test_invalid_plaintext_base64_rejected(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers)
    response = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "data-key", "plaintext_b64": "not-base64!"},
        headers=alice_headers,
    )
    assert response.status_code == 400


def test_signing_key_cannot_encrypt(unlocked_client: TestClient, alice_headers) -> None:
    unlocked_client.post(
        "/v1/transit/signing-keys",
        json={"key_name": "signer", "signing_algorithm": "ED25519"},
        headers=alice_headers,
    )
    response = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "signer", "plaintext_b64": b64("x")},
        headers=alice_headers,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_KEY_USAGE"


def test_revoked_key_cannot_encrypt_or_decrypt(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers, "rev")
    token = unlocked_client.post(
        "/v1/transit/encrypt", json={"key_name": "rev", "plaintext_b64": b64("x")}, headers=alice_headers
    ).json()["ciphertext"]
    unlocked_client.post("/v1/transit/keys/rev/revoke", headers=alice_headers)
    assert unlocked_client.post(
        "/v1/transit/encrypt", json={"key_name": "rev", "plaintext_b64": b64("x")}, headers=alice_headers
    ).status_code == 409
    assert unlocked_client.post(
        "/v1/transit/decrypt", json={"ciphertext": token}, headers=alice_headers
    ).status_code == 409


def test_cross_user_cannot_decrypt(unlocked_client: TestClient, alice_bob_headers) -> None:
    alice, bob = alice_bob_headers
    create_key(unlocked_client, alice, "alice-key")
    token = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "alice-key", "plaintext_b64": b64("alice")},
        headers=alice,
    ).json()["ciphertext"]
    response = unlocked_client.post("/v1/transit/decrypt", json={"ciphertext": token}, headers=bob)
    assert response.status_code == 403


def test_key_permission_precedes_vault_state(unlocked_client: TestClient, alice_bob_headers) -> None:
    alice, bob = alice_bob_headers
    create_key(unlocked_client, alice, "alice-key")
    unlocked_client.post("/v1/vault/lock")
    response = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "alice-key", "plaintext_b64": b64("x")},
        headers=bob,
    )
    assert response.status_code == 403
