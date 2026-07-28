"""Section IV extra credit: Transit key rotation (+0.4).

The requirement is "versioned named keys, still able to decrypt old ciphertext",
so the central test is that data encrypted before a rotation still decrypts
afterwards, while new data uses the new version.
"""

import base64
import sqlite3
from contextlib import closing

from fastapi.testclient import TestClient

from tests.conftest import b64


def create_key(client: TestClient, headers, name: str) -> None:
    assert client.post(
        "/v1/transit/keys", json={"key_name": name}, headers=headers
    ).status_code == 201


def create_signer(client: TestClient, headers, name: str) -> None:
    assert client.post(
        "/v1/transit/signing-keys",
        json={"key_name": name, "signing_algorithm": "ED25519"},
        headers=headers,
    ).status_code == 201


def encrypt(client: TestClient, headers, name: str, payload: str) -> dict:
    response = client.post(
        "/v1/transit/encrypt",
        json={"key_name": name, "plaintext_b64": b64(payload)},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def rotate(client: TestClient, headers, name: str) -> dict:
    response = client.post(f"/v1/transit/keys/{name}/rotate", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_rotation_appends_a_version(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers, "rot")
    assert rotate(unlocked_client, alice_headers, "rot")["latest_version"] == 2
    body = rotate(unlocked_client, alice_headers, "rot")
    assert body["latest_version"] == 3
    assert body["versions"] == [1, 2, 3]


def test_rotation_replaces_the_key_material(
    unlocked_client: TestClient, alice_headers, vault_paths
) -> None:
    """A rotation must produce genuinely new key material, not re-wrap the old."""
    create_key(unlocked_client, alice_headers, "rot")
    rotate(unlocked_client, alice_headers, "rot")
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        materials = [
            row[0]
            for row in conn.execute(
                "SELECT encrypted_key_material_b64 FROM named_key_versions ORDER BY version"
            )
        ]
    assert len(materials) == 2 and materials[0] != materials[1]


def test_old_ciphertext_still_decrypts_after_rotation(
    unlocked_client: TestClient, alice_headers
) -> None:
    create_key(unlocked_client, alice_headers, "rot")
    before = encrypt(unlocked_client, alice_headers, "rot", "written-before-rotation")
    assert before["key_version"] == 1
    assert before["ciphertext"].startswith("vault:rot:")

    rotate(unlocked_client, alice_headers, "rot")

    after = encrypt(unlocked_client, alice_headers, "rot", "written-after-rotation")
    assert after["key_version"] == 2
    # Only rotated keys carry the explicit version segment.
    assert after["ciphertext"].startswith("vault:v2:rot:")

    for token, expected in ((before["ciphertext"], b"written-before-rotation"),
                            (after["ciphertext"], b"written-after-rotation")):
        response = unlocked_client.post(
            "/v1/transit/decrypt", json={"ciphertext": token}, headers=alice_headers
        )
        assert response.status_code == 200, response.text
        assert base64.b64decode(response.json()["plaintext_b64"]) == expected


def test_ciphertext_naming_a_missing_version_is_rejected(
    unlocked_client: TestClient, alice_headers
) -> None:
    create_key(unlocked_client, alice_headers, "rot")
    token = encrypt(unlocked_client, alice_headers, "rot", "x")["ciphertext"]
    _, key_name, payload = token.split(":", 2)
    forged = f"vault:v9:{key_name}:{payload}"
    response = unlocked_client.post(
        "/v1/transit/decrypt", json={"ciphertext": forged}, headers=alice_headers
    )
    assert response.status_code == 404
    assert response.json()["error"] == "KEY_VERSION_NOT_FOUND"


def test_version_is_bound_into_the_associated_data(
    unlocked_client: TestClient, alice_headers
) -> None:
    """Relabelling a v1 ciphertext as v2 must fail rather than decrypt.

    Without the version in the AAD an attacker could swap the version segment
    and have the server try the wrong key; the tag check has to catch that.
    """
    create_key(unlocked_client, alice_headers, "rot")
    token = encrypt(unlocked_client, alice_headers, "rot", "x")["ciphertext"]
    rotate(unlocked_client, alice_headers, "rot")
    _, key_name, payload = token.split(":", 2)
    response = unlocked_client.post(
        "/v1/transit/decrypt",
        json={"ciphertext": f"vault:v2:{key_name}:{payload}"},
        headers=alice_headers,
    )
    assert response.status_code == 409
    assert response.json()["error"] == "TAMPER_DETECTED"


def test_signing_key_rotation_keeps_old_signatures_verifiable(
    unlocked_client: TestClient, alice_headers
) -> None:
    create_signer(unlocked_client, alice_headers, "sig")
    message = b64("message signed before rotation")
    signed = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "sig",
            "message_b64": message,
            "message_type": "RAW",
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    ).json()
    assert signed["key_version"] == 1

    rotate(unlocked_client, alice_headers, "sig")

    verified = unlocked_client.post(
        "/v1/transit/verify",
        json={
            "key_name": "sig",
            "message_b64": message,
            "message_type": "RAW",
            "signature_b64": signed["signature_b64"],
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    ).json()
    # Every version is tried, and the response says which one matched.
    assert verified["signature_valid"] is True
    assert verified["key_version"] == 1


def test_verify_can_be_pinned_to_one_version(
    unlocked_client: TestClient, alice_headers
) -> None:
    create_signer(unlocked_client, alice_headers, "sig")
    message = b64("pinned")
    signature = unlocked_client.post(
        "/v1/transit/sign",
        json={
            "key_name": "sig",
            "message_b64": message,
            "message_type": "RAW",
            "signing_algorithm": "ED25519",
        },
        headers=alice_headers,
    ).json()["signature_b64"]
    rotate(unlocked_client, alice_headers, "sig")

    pinned = unlocked_client.post(
        "/v1/transit/verify",
        json={
            "key_name": "sig",
            "message_b64": message,
            "message_type": "RAW",
            "signature_b64": signature,
            "signing_algorithm": "ED25519",
            "key_version": 2,
        },
        headers=alice_headers,
    ).json()
    assert pinned["signature_valid"] is False
    assert pinned["key_version"] is None


def test_rotation_metadata_never_exposes_key_material(
    unlocked_client: TestClient, alice_headers
) -> None:
    create_key(unlocked_client, alice_headers, "rot")
    serialized = str(rotate(unlocked_client, alice_headers, "rot"))
    for leak in ("encrypted_key_material", "public_key", "nonce", "tag_b64"):
        assert leak not in serialized


def test_cross_user_cannot_rotate(unlocked_client: TestClient, alice_bob_headers) -> None:
    alice, bob = alice_bob_headers
    create_key(unlocked_client, alice, "alice-key")
    response = unlocked_client.post("/v1/transit/keys/alice-key/rotate", headers=bob)
    assert response.status_code == 403
    assert response.json()["error"] == "PERMISSION_DENIED"


def test_rotation_requires_unlocked_vault(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers, "rot")
    unlocked_client.post("/v1/vault/lock")
    response = unlocked_client.post("/v1/transit/keys/rot/rotate", headers=alice_headers)
    assert response.status_code == 423
    assert response.json()["error"] == "VAULT_LOCKED"


def test_rotation_requires_authentication(unlocked_client: TestClient, alice_headers) -> None:
    create_key(unlocked_client, alice_headers, "rot")
    assert unlocked_client.post("/v1/transit/keys/rot/rotate").status_code == 401
