import base64

from fastapi.testclient import TestClient

from tests.conftest import ALICE_EMAIL, b64


def test_complete_assignment_flow(unlocked_client: TestClient, alice_headers) -> None:
    path = f"secret/{ALICE_EMAIL}/demo"
    assert unlocked_client.post(
        "/v1/kv/entries", json={"path": path, "data": {"api_key": "demo-secret"}}, headers=alice_headers
    ).status_code == 200
    assert unlocked_client.get("/v1/kv/entries", params={"path": path}, headers=alice_headers).json()["data"]["api_key"] == "demo-secret"

    assert unlocked_client.post(
        "/v1/transit/keys", json={"key_name": "demo-aes"}, headers=alice_headers
    ).status_code == 201
    encrypted = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "demo-aes", "plaintext_b64": b64("transit secret")},
        headers=alice_headers,
    ).json()["ciphertext"]
    decrypted = unlocked_client.post(
        "/v1/transit/decrypt", json={"ciphertext": encrypted}, headers=alice_headers
    ).json()["plaintext_b64"]
    assert base64.b64decode(decrypted) == b"transit secret"

    assert unlocked_client.post(
        "/v1/transit/signing-keys",
        json={"key_name": "demo-sign", "signing_algorithm": "ED25519"},
        headers=alice_headers,
    ).status_code == 201
    message = b64("signed payload")
    signature = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "demo-sign",
            "message_b64": message,
            "message_type": "RAW",
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    ).json()["signature_b64"]
    verified = unlocked_client.post(
        "/v1/transit/verify",
        json={
            "key_name": "demo-sign",
            "message_b64": message,
            "message_type": "RAW",
            "signature_b64": signature,
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    )
    assert verified.json()["signature_valid"] is True
