"""Section IV extra credit: KV versioning (+0.3).

The mandatory behaviour of Feature 1.1 must survive untouched: a read without a
version still returns the newest value. These tests cover what versioning adds
on top, including the rollback attack that binding the version into the AEAD
associated data is there to stop.
"""

import sqlite3
from contextlib import closing

from fastapi.testclient import TestClient

from tests.conftest import ALICE_EMAIL


PATH = f"secret/{ALICE_EMAIL}/rotating"


def write(client: TestClient, headers, value: str) -> dict:
    response = client.post(
        "/v1/kv/entries", json={"path": PATH, "data": {"value": value}}, headers=headers
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_each_write_creates_a_new_version(unlocked_client: TestClient, alice_headers) -> None:
    assert write(unlocked_client, alice_headers, "one")["version"] == 1
    assert write(unlocked_client, alice_headers, "two")["version"] == 2
    assert write(unlocked_client, alice_headers, "three")["version"] == 3


def test_created_at_tracks_the_first_write(unlocked_client: TestClient, alice_headers) -> None:
    first = write(unlocked_client, alice_headers, "one")
    second = write(unlocked_client, alice_headers, "two")
    assert second["created_at"] == first["created_at"]
    assert second["updated_at"] >= first["updated_at"]


def test_old_versions_remain_readable(unlocked_client: TestClient, alice_headers) -> None:
    write(unlocked_client, alice_headers, "one")
    write(unlocked_client, alice_headers, "two")

    latest = unlocked_client.get(
        "/v1/kv/entries", params={"path": PATH}, headers=alice_headers
    ).json()
    assert latest["data"]["value"] == "two" and latest["version"] == 2

    historical = unlocked_client.get(
        "/v1/kv/entries", params={"path": PATH, "version": 1}, headers=alice_headers
    ).json()
    assert historical["data"]["value"] == "one"
    assert historical["version"] == 1 and historical["latest_version"] == 2


def test_version_listing_reports_history(unlocked_client: TestClient, alice_headers) -> None:
    write(unlocked_client, alice_headers, "one")
    write(unlocked_client, alice_headers, "two")
    body = unlocked_client.get(
        "/v1/kv/entries/versions", params={"path": PATH}, headers=alice_headers
    ).json()
    assert body["latest_version"] == 2
    assert [item["version"] for item in body["versions"]] == [1, 2]
    # Metadata only: no ciphertext and no plaintext in the listing.
    assert "one" not in str(body) and "ciphertext" not in str(body)


def test_unknown_version_is_not_found(unlocked_client: TestClient, alice_headers) -> None:
    write(unlocked_client, alice_headers, "one")
    response = unlocked_client.get(
        "/v1/kv/entries", params={"path": PATH, "version": 7}, headers=alice_headers
    )
    assert response.status_code == 404


def test_version_zero_rejected_by_validation(unlocked_client: TestClient, alice_headers) -> None:
    write(unlocked_client, alice_headers, "one")
    response = unlocked_client.get(
        "/v1/kv/entries", params={"path": PATH, "version": 0}, headers=alice_headers
    )
    assert response.status_code == 422


def test_rollback_by_copying_an_old_version_is_detected(
    unlocked_client: TestClient, alice_headers, vault_paths
) -> None:
    """The attack versioning would otherwise enable.

    Someone with write access to the database copies version 1's ciphertext
    over version 2, silently reverting a rotated credential. Because the version
    number is part of the associated data, the moved blob fails tag
    verification instead of decrypting.
    """
    write(unlocked_client, alice_headers, "old-password")
    write(unlocked_client, alice_headers, "new-password")

    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        old = conn.execute(
            "SELECT nonce_b64, ciphertext_b64, tag_b64 FROM kv_versions WHERE version = 1"
        ).fetchone()
        conn.execute(
            "UPDATE kv_versions SET nonce_b64 = ?, ciphertext_b64 = ?, tag_b64 = ? WHERE version = 2",
            old,
        )
        conn.commit()

    response = unlocked_client.get(
        "/v1/kv/entries", params={"path": PATH}, headers=alice_headers
    )
    assert response.status_code == 409
    assert response.json()["error"] == "TAMPER_DETECTED"


def test_delete_removes_every_version(
    unlocked_client: TestClient, alice_headers, vault_paths
) -> None:
    write(unlocked_client, alice_headers, "one")
    write(unlocked_client, alice_headers, "two")
    assert unlocked_client.delete(
        "/v1/kv/entries", params={"path": PATH}, headers=alice_headers
    ).status_code == 204
    with closing(sqlite3.connect(vault_paths["database"])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM kv_versions").fetchone()[0] == 0
    assert unlocked_client.get(
        "/v1/kv/entries", params={"path": PATH, "version": 1}, headers=alice_headers
    ).status_code == 404


def test_cross_user_cannot_list_versions(unlocked_client: TestClient, alice_bob_headers) -> None:
    """Feature 1.2 applies to the new endpoint too, otherwise version listing
    would leak which paths another user owns."""
    alice, bob = alice_bob_headers
    unlocked_client.post("/v1/kv/entries", json={"path": PATH, "data": {"v": 1}}, headers=alice)
    response = unlocked_client.get(
        "/v1/kv/entries/versions", params={"path": PATH}, headers=bob
    )
    assert response.status_code == 403
    assert response.json()["error"] == "PERMISSION_DENIED"


def test_versions_require_unlocked_vault(unlocked_client: TestClient, alice_headers) -> None:
    unlocked_client.post("/v1/kv/entries", json={"path": PATH, "data": {"v": 1}}, headers=alice_headers)
    unlocked_client.post("/v1/vault/lock")
    response = unlocked_client.get(
        "/v1/kv/entries/versions", params={"path": PATH}, headers=alice_headers
    )
    assert response.status_code == 423
    assert response.json()["error"] == "VAULT_LOCKED"


def test_history_is_ciphertext_on_disk(
    unlocked_client: TestClient, alice_headers, vault_paths
) -> None:
    write(unlocked_client, alice_headers, "superseded-secret")
    write(unlocked_client, alice_headers, "current-secret")
    raw = vault_paths["database"].read_bytes()
    # Retaining history must not weaken 1.1: superseded values stay encrypted.
    assert b"superseded-secret" not in raw
    assert b"current-secret" not in raw
