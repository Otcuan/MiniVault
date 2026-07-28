"""Generate the evidence files section VI asks for.

Produces, in `data/samples/`:

* `kv_encrypted_sample.json`    - KV rows exactly as they sit on disk, so a
                                  grader can confirm no plaintext is stored.
* `transit_ciphertext_sample.json` - Transit ciphertext, signatures, and a
                                  before/after rotation pair.
* `vault_config_sample.json`    - the wrapped DEK and KDF parameters.
* `audit_chain_sample.json`     - the hash-chained audit log plus its
                                  verification result.
* `mini_vault_sample.db`        - the whole SQLite database, for inspection.

Everything is produced by driving the real HTTP API, so the samples cannot drift
away from what the running service actually writes.

Run:  python -m scripts.generate_samples
"""

import base64
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path

# Cheap Argon2 parameters: this script only produces illustrative data and the
# real cost would make it slow for no benefit. Must be set before importing the
# application.
import os

os.environ.setdefault("MINIVAULT_KDF_TIME_COST", "1")
os.environ.setdefault("MINIVAULT_KDF_MEMORY_COST", "8192")
os.environ.setdefault("MINIVAULT_PASSWORD_TIME_COST", "1")
os.environ.setdefault("MINIVAULT_PASSWORD_MEMORY_COST", "8192")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from main import create_app  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "samples"

# Sample credentials only. They exist so the demo is reproducible and are not
# used by any real deployment.
MASTER = "Sample-Master-Key-2026!"
ALICE = ("alice@minivault.test", "Alice-Sample-Passw0rd!")
BOB = ("bob@minivault.test", "Bobby-Sample-Passw0rd!")

# Marker values the checks below look for in the raw database.
DB_PASSWORD = "PLAINTEXT-DB-PASSWORD-MARKER"
ROTATED_PASSWORD = "PLAINTEXT-ROTATED-MARKER"
TRANSIT_PAYLOAD = "PLAINTEXT-TRANSIT-MARKER"


def b64(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.b64encode(value).decode("ascii")


def main() -> int:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    (ROOT / "data" / "logs").mkdir(parents=True, exist_ok=True)

    work = SAMPLES / ".build"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    config_path = work / "vault_config.json"
    database_path = work / "mini_vault.db"

    app = create_app(config_path, database_path)
    with TestClient(app) as client:
        alice, bob = bootstrap(client)
        kv = build_kv_samples(client, alice)
        transit = build_transit_samples(client, alice, bob)
        audit = build_audit_samples(client, alice, bob)

    write_json("kv_encrypted_sample.json", kv)
    write_json("transit_ciphertext_sample.json", transit)
    write_json("vault_config_sample.json", json.loads(config_path.read_text("utf-8")))
    write_json("audit_chain_sample.json", audit)
    shutil.copy(database_path, SAMPLES / "mini_vault_sample.db")

    failures = check_no_plaintext(database_path)
    shutil.rmtree(work)

    for line in sorted(path.name for path in SAMPLES.iterdir()):
        print(f"  data/samples/{line}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("OK: no plaintext marker found anywhere in the sample database.")
    return 0


def bootstrap(client: TestClient) -> tuple[dict, dict]:
    assert client.post("/v1/vault/init", json={"master_passphrase": MASTER}).status_code == 201
    assert client.post("/v1/vault/unlock", json={"master_passphrase": MASTER}).status_code == 200
    return login(client, *ALICE), login(client, *BOB)


def login(client: TestClient, email: str, passphrase: str) -> dict:
    assert client.post(
        "/v1/auth/register",
        json={"email": email, "passphrase": passphrase, "confirm_passphrase": passphrase},
    ).status_code == 201
    token = client.post(
        "/v1/auth/login", json={"email": email, "passphrase": passphrase}
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def build_kv_samples(client: TestClient, alice: dict) -> dict:
    path = f"secret/{ALICE[0]}/database"
    client.post("/v1/kv/entries", json={"path": path, "data": {"password": DB_PASSWORD}}, headers=alice)
    # A second write demonstrates versioning: v1 is kept, still encrypted.
    client.post(
        "/v1/kv/entries",
        json={"path": path, "data": {"password": ROTATED_PASSWORD}},
        headers=alice,
    )
    versions = client.get(
        "/v1/kv/entries/versions", params={"path": path}, headers=alice
    ).json()
    return {
        "description": (
            "KV rows as stored on disk. Only nonce/ciphertext/tag are persisted; "
            "the plaintext markers written by this script appear nowhere."
        ),
        "path": path,
        "aead": "AES-256-GCM, AAD = kv:<owner>:<path>:v<version>",
        "version_metadata": versions,
        "rows": dump_table(
            client.app.state.database.path,
            """
            SELECT r.owner_email, r.path, v.version, v.nonce_b64, v.ciphertext_b64,
                   v.tag_b64, v.created_at
            FROM kv_records r JOIN kv_versions v ON v.record_id = r.id
            ORDER BY v.version
            """,
        ),
    }


def build_transit_samples(client: TestClient, alice: dict, bob: dict) -> dict:
    client.post("/v1/transit/keys", json={"key_name": "demo-aes"}, headers=alice)
    before = client.post(
        "/v1/transit/encrypt",
        json={"key_name": "demo-aes", "plaintext_b64": b64(TRANSIT_PAYLOAD)},
        headers=alice,
    ).json()

    client.post("/v1/transit/keys/demo-aes/rotate", headers=alice)
    after = client.post(
        "/v1/transit/encrypt",
        json={"key_name": "demo-aes", "plaintext_b64": b64(TRANSIT_PAYLOAD)},
        headers=alice,
    ).json()

    client.post(
        "/v1/transit/signing-keys",
        json={"key_name": "demo-sign", "signing_algorithm": "ED25519"},
        headers=alice,
    )
    message = "message signed by Mini Vault"
    signed = client.post(
        "/v1/transit/sign",
        json={
            "key_name": "demo-sign",
            "message_b64": b64(message),
            "message_type": "RAW",
            "signing_algorithm": "ED25519",
        },
        headers=alice,
    ).json()

    def verify(msg: str) -> dict:
        return client.post(
            "/v1/transit/verify",
            json={
                "key_name": "demo-sign",
                "message_b64": b64(msg),
                "message_type": "RAW",
                "signature_b64": signed["signature_b64"],
                "signing_algorithm": "ED25519",
            },
            headers=alice,
        ).json()

    denied = client.post(
        "/v1/transit/decrypt", json={"ciphertext": before["ciphertext"]}, headers=bob
    )

    return {
        "description": (
            "Transit ciphertext and signatures. Un-rotated keys use the "
            "vault:<key_name>:<b64> framing required by section 2.2; after a "
            "rotation the version segment appears and older ciphertext still "
            "decrypts."
        ),
        "encrypt_decrypt": {
            "before_rotation": before,
            "after_rotation": after,
            "decrypt_before_rotation_still_works": client.post(
                "/v1/transit/decrypt",
                json={"ciphertext": before["ciphertext"]},
                headers=alice,
            ).json(),
        },
        "sign_verify": {
            "signed": signed,
            "message": message,
            "sha256_of_message": hashlib.sha256(message.encode()).hexdigest(),
            "verify_original": verify(message),
            "verify_tampered": verify(message + "!"),
        },
        "cross_user_denied": {
            "status_code": denied.status_code,
            "body": denied.json(),
        },
        "stored_key_rows": dump_table(
            client.app.state.database.path,
            """
            SELECT k.key_name, k.owner_email, k.key_usage, k.signing_algorithm,
                   v.version, v.nonce_b64, v.encrypted_key_material_b64, v.tag_b64
            FROM named_keys k JOIN named_key_versions v ON v.key_id = k.id
            ORDER BY k.key_name, v.version
            """,
        ),
    }


def build_audit_samples(client: TestClient, alice: dict, bob: dict) -> dict:
    # Denied cross-user attempts are what sections 1.2 and 2.3 require logging.
    client.get(
        "/v1/kv/entries",
        params={"path": f"secret/{ALICE[0]}/database"},
        headers=bob,
    )
    client.post(
        "/v1/transit/encrypt",
        json={"key_name": "demo-aes", "plaintext_b64": b64("x")},
        headers=bob,
    )
    return {
        "description": (
            "Hash-chained audit log. Each entry_hash commits to the previous "
            "one, so editing, deleting or reordering entries breaks "
            "verification."
        ),
        "verification": client.get("/v1/audit/verify", headers=alice).json(),
        "entries": dump_table(
            client.app.state.database.path,
            "SELECT * FROM audit_logs ORDER BY sequence",
        ),
    }


def dump_table(database_path: Path, query: str) -> list[dict]:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(query)]
    finally:
        connection.close()


def check_no_plaintext(database_path: Path) -> list[str]:
    """Fail loudly if any marker leaked into the database in the clear."""
    raw = database_path.read_bytes()
    return [
        f"plaintext marker {marker!r} found in the database"
        for marker in (DB_PASSWORD, ROTATED_PASSWORD, TRANSIT_PAYLOAD)
        if marker.encode() in raw
    ]


def write_json(name: str, payload: object) -> None:
    (SAMPLES / name).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    raise SystemExit(main())
