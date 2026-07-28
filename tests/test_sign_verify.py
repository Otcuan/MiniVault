import hashlib

from fastapi.testclient import TestClient

from tests.conftest import b64


def create_signer(client: TestClient, headers, name="signer") -> None:
    assert client.post(
        "/v1/transit/signing-keys",
        json={"key_name": name, "signing_algorithm": "ED25519"},
        headers=headers,
    ).status_code == 201


def sign(client: TestClient, headers, name: str, message_b64: str, message_type="RAW") -> str:
    response = client.post(
        "/v1/transit/sign",
        json={
            "key_name": name,
            "message_b64": message_b64,
            "message_type": message_type,
            "signing_algorithm": "ED25519",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()["signature_b64"]


def verify(client, headers, name, message_b64, signature_b64, message_type="RAW"):
    return client.post(
        "/v1/transit/verify",
        json={
            "key_name": name,
            "message_b64": message_b64,
            "message_type": message_type,
            "signature_b64": signature_b64,
            "signing_algorithm": "ED25519",
        },
        headers=headers,
    )


def test_raw_sign_verify(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers)
    message = b64("important message")
    signature = sign(unlocked_client, alice_headers, "signer", message)
    assert verify(unlocked_client, alice_headers, "signer", message, signature).json()["signature_valid"] is True


def test_digest_sign_verify(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers)
    digest = b64(hashlib.sha256(b"important message").digest())
    signature = sign(unlocked_client, alice_headers, "signer", digest, "DIGEST")
    assert verify(unlocked_client, alice_headers, "signer", digest, signature, "DIGEST").json()["signature_valid"] is True


def test_wrong_digest_length_rejected(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers)
    response = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "signer",
            "message_b64": b64(b"short"),
            "message_type": "DIGEST",
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_DIGEST_LENGTH"


def test_tampered_message_returns_false(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers)
    signature = sign(unlocked_client, alice_headers, "signer", b64("original"))
    response = verify(unlocked_client, alice_headers, "signer", b64("changed"), signature)
    assert response.status_code == 200
    assert response.json()["signature_valid"] is False


def test_cross_key_signature_returns_false(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers, "key-a")
    create_signer(unlocked_client, alice_headers, "key-b")
    message = b64("same")
    signature = sign(unlocked_client, alice_headers, "key-a", message)
    assert verify(unlocked_client, alice_headers, "key-b", message, signature).json()["signature_valid"] is False


def test_malformed_signature_returns_false_not_exception(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers)
    response = verify(unlocked_client, alice_headers, "signer", b64("x"), "not-base64!")
    assert response.status_code == 200
    assert response.json()["signature_valid"] is False


def test_algorithm_mismatch_rejected(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers)
    response = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "signer",
            "message_b64": b64("x"),
            "message_type": "RAW",
            "signing_algorithm": "RSA_2048",
        },
        headers=alice_headers,
    )
    assert response.status_code == 400


def test_aes_key_cannot_sign(unlocked_client: TestClient, alice_headers) -> None:
    unlocked_client.post("/v1/transit/keys", json={"key_name": "aes"}, headers=alice_headers)
    response = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "aes",
            "message_b64": b64("x"),
            "message_type": "RAW",
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_KEY_USAGE"


def test_revoked_signing_key_refused(unlocked_client: TestClient, alice_headers) -> None:
    create_signer(unlocked_client, alice_headers)
    message = b64("x")
    signature = sign(unlocked_client, alice_headers, "signer", message)
    unlocked_client.post("/v1/transit/keys/signer/revoke", headers=alice_headers)

    signed = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "signer",
            "message_b64": message,
            "message_type": "RAW",
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    )
    # Both sign and verify refuse: the key material is gone, not merely flagged.
    assert signed.status_code == 403
    assert verify(unlocked_client, alice_headers, "signer", message, signature).status_code == 403


def test_cross_user_cannot_sign_with_foreign_key(unlocked_client: TestClient, alice_bob_headers) -> None:
    alice, bob = alice_bob_headers
    create_signer(unlocked_client, alice, "alice-signer")
    response = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "alice-signer",
            "message_b64": b64("x"),
            "message_type": "RAW",
            "signing_algorithm": "ED25519",
        },
        headers=bob,
    )
    assert response.status_code == 403
