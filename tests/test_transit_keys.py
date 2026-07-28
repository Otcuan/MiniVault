import sqlite3
from contextlib import closing

from fastapi.testclient import TestClient

from tests.conftest import ALICE_EMAIL


def test_create_aes_key_returns_metadata_only(unlocked_client: TestClient, alice_headers) -> None:
    response = unlocked_client.post("/v1/transit/keys", json={"key_name": "payments"}, headers=alice_headers)
    assert response.status_code == 201
    body = response.json()
    assert body["key_usage"] == "ENCRYPT_DECRYPT"
    assert "encrypted_key_material_b64" not in body
    assert "key_material" not in body


def test_aes_key_material_is_encrypted_on_disk(unlocked_client: TestClient, alice_headers, vault_paths) -> None:
    unlocked_client.post("/v1/transit/keys", json={"key_name": "payments"}, headers=alice_headers)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        row = conn.execute(
            """
            SELECT v.nonce_b64, v.encrypted_key_material_b64, v.tag_b64
            FROM named_keys k JOIN named_key_versions v ON v.key_id = k.id
            WHERE k.key_name = 'payments'
            """
        ).fetchone()
    assert row is not None
    assert all(isinstance(value, str) and value for value in row)
    assert len(row[1]) >= 40


def test_create_signing_key_stores_encrypted_private_and_public(unlocked_client: TestClient, alice_headers, vault_paths) -> None:
    response = unlocked_client.post(
        "/v1/transit/signing-keys",
        json={"key_name": "signer", "signing_algorithm": "ED25519"},
        headers=alice_headers,
    )
    assert response.status_code == 201
    assert response.json()["key_usage"] == "SIGN_VERIFY"
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        row = conn.execute(
            """
            SELECT v.encrypted_key_material_b64, v.public_key_b64
            FROM named_keys k JOIN named_key_versions v ON v.key_id = k.id
            WHERE k.key_name = 'signer'
            """
        ).fetchone()
    assert row[0] and row[1]
    assert row[0] != row[1]


def test_list_keys_does_not_expose_material(unlocked_client: TestClient, alice_headers) -> None:
    unlocked_client.post("/v1/transit/keys", json={"key_name": "a"}, headers=alice_headers)
    unlocked_client.post(
        "/v1/transit/signing-keys", json={"key_name": "b", "signing_algorithm": "ED25519"}, headers=alice_headers
    )
    body = unlocked_client.get("/v1/transit/keys", headers=alice_headers).json()
    assert [item["key_name"] for item in body["keys"]] == ["a", "b"]
    serialized = str(body)
    assert "encrypted_key_material" not in serialized
    assert "public_key_b64" not in serialized


def test_duplicate_key_name_rejected(unlocked_client: TestClient, alice_headers) -> None:
    assert unlocked_client.post("/v1/transit/keys", json={"key_name": "dup"}, headers=alice_headers).status_code == 201
    assert unlocked_client.post("/v1/transit/keys", json={"key_name": "dup"}, headers=alice_headers).status_code == 409


def test_invalid_key_name_rejected(unlocked_client: TestClient, alice_headers) -> None:
    response = unlocked_client.post("/v1/transit/keys", json={"key_name": "bad:key"}, headers=alice_headers)
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_KEY_NAME"


def test_revoke_key_permanently_deletes_material(
    unlocked_client: TestClient, alice_headers, vault_paths
) -> None:
    """Section 2.1 asks revoke_key to permanently delete the key.

    So this asserts more than an HTTP status: no wrapped key material for that
    name may survive anywhere in the database.
    """
    unlocked_client.post("/v1/transit/keys", json={"key_name": "revoked"}, headers=alice_headers)
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        material = conn.execute(
            """
            SELECT v.encrypted_key_material_b64
            FROM named_keys k JOIN named_key_versions v ON v.key_id = k.id
            WHERE k.key_name = 'revoked'
            """
        ).fetchone()[0]

    response = unlocked_client.post("/v1/transit/keys/revoked/revoke", headers=alice_headers)
    assert response.status_code == 200
    assert response.json() == {"key_name": "revoked", "deleted": True}

    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM named_keys WHERE key_name = 'revoked'"
        ).fetchone()[0] == 0
        # ON DELETE CASCADE must have taken the version rows with it.
        assert conn.execute(
            "SELECT COUNT(*) FROM named_key_versions WHERE encrypted_key_material_b64 = ?",
            (material,),
        ).fetchone()[0] == 0
    assert unlocked_client.get("/v1/transit/keys", headers=alice_headers).json()["keys"] == []


def test_create_key_requires_unlocked_vault(unlocked_client: TestClient, alice_headers) -> None:
    unlocked_client.post("/v1/vault/lock")
    response = unlocked_client.post("/v1/transit/keys", json={"key_name": "locked"}, headers=alice_headers)
    assert response.status_code == 423


def test_cross_user_key_is_generic_permission_denied(unlocked_client: TestClient, alice_bob_headers) -> None:
    alice, bob = alice_bob_headers
    unlocked_client.post("/v1/transit/keys", json={"key_name": "alice-key"}, headers=alice)
    response = unlocked_client.post(
        "/v1/transit/encrypt",
        json={"key_name": "alice-key", "plaintext_b64": "aGVsbG8="},
        headers=bob,
    )
    assert response.status_code == 403
    assert response.json()["error"] == "PERMISSION_DENIED"

def test_list_keys_requires_unlocked_vault(unlocked_client: TestClient, alice_headers) -> None:
    create_response = unlocked_client.post(
        "/v1/transit/keys",
        json={"key_name": "locked-list-key"},
        headers=alice_headers,
    )
    assert create_response.status_code == 201

    lock_response = unlocked_client.post(
        "/v1/vault/lock"
    )
    assert lock_response.status_code == 200

    response = unlocked_client.get(
        "/v1/transit/keys",
        headers=alice_headers,
    )

    assert response.status_code == 423
    assert response.json()["error"] == "VAULT_LOCKED"
