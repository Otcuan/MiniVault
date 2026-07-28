import json
from typing import Any, Optional

from cryptography.exceptions import InvalidTag

from src.audit.repository import AuditRepository
from src.core.crypto import EncryptedBlob, decrypt_aes_gcm, encrypt_aes_gcm
from src.core.encoding import decode_b64, encode_b64
from src.core.vault import VaultService
from src.kv.exceptions import (
    InvalidVersionError,
    PermissionDeniedError,
    RecordNotFoundError,
    RecordTamperedError,
)
from src.kv.paths import extract_owner_email_from_path
from src.kv.repository import KvRepository


class KvService:
    """Feature 1: encrypted-at-rest KV storage with ownership access control.

    Section IV extra: every overwrite keeps the previous ciphertext as an older
    version. Reads without an explicit version still resolve to the newest one,
    so the mandatory behaviour in 1.1 is unchanged from the caller's side.
    """

    def __init__(
        self,
        vault: VaultService,
        records: KvRepository,
        audit: AuditRepository,
    ) -> None:
        self._vault = vault
        self._records = records
        self._audit = audit

    def _authorize(self, requester_email: str, path: str) -> None:
        """Feature 1.2: the session email must own the path prefix.

        Runs before any crypto and before the Vault-state check, and answers
        with the same error whether the path is foreign or malformed, so a
        caller cannot probe which paths exist.
        """
        try:
            path_owner = extract_owner_email_from_path(path)
        except ValueError:
            path_owner = None
        if path_owner != requester_email:
            self._audit.log_denied_access(requester_email, "kv_path", path)
            raise PermissionDeniedError()

    @staticmethod
    def _aad(owner_email: str, path: str, version: int) -> bytes:
        """Associated data binds ciphertext to owner, path and version.

        Without the version an attacker with database write access could roll a
        secret back by copying an old ciphertext row over the current one; with
        it, the moved blob fails tag verification.
        """
        return f"kv:{owner_email}:{path}:v{version}".encode("utf-8")

    @staticmethod
    def _normalize_version(version: Optional[int]) -> Optional[int]:
        if version is None:
            return None
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise InvalidVersionError()
        return version

    def write(self, owner_email: str, path: str, data: dict[str, Any]) -> dict:
        # Ownership is checked before Vault state to avoid a state oracle.
        self._authorize(owner_email, path)
        self._vault.require_unlocked()
        plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        dek = self._vault.get_dek()

        def encrypt_for(version: int) -> tuple[str, str, str]:
            blob = encrypt_aes_gcm(dek, plaintext, self._aad(owner_email, path, version))
            return encode_b64(blob.nonce), encode_b64(blob.ciphertext), encode_b64(blob.tag)

        return self._records.append_version(owner_email, path, encrypt_for)

    def read(
        self, owner_email: str, path: str, version: Optional[int] = None
    ) -> dict[str, Any]:
        self._authorize(owner_email, path)
        requested = self._normalize_version(version)
        self._vault.require_unlocked()
        record = self._records.get_version(owner_email, path, requested)
        if record is None:
            raise RecordNotFoundError()
        try:
            plaintext = decrypt_aes_gcm(
                self._vault.get_dek(),
                EncryptedBlob(
                    nonce=decode_b64(record["nonce_b64"]),
                    ciphertext=decode_b64(record["ciphertext_b64"]),
                    tag=decode_b64(record["tag_b64"]),
                ),
                self._aad(owner_email, path, int(record["version"])),
            )
            decoded = json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            # Tag mismatch or garbage plaintext: refuse outright rather than
            # returning data that "might be right, might be wrong".
            raise RecordTamperedError() from exc
        if not isinstance(decoded, dict):
            raise RecordTamperedError()
        return {
            "data": decoded,
            "version": int(record["version"]),
            "latest_version": int(record["latest_version"]),
            "created_at": record["created_at"],
        }

    def versions(self, owner_email: str, path: str) -> dict[str, Any]:
        """Section IV: history metadata only, no plaintext and no ciphertext."""
        self._authorize(owner_email, path)
        self._vault.require_unlocked()
        rows = self._records.list_versions(owner_email, path)
        if not rows:
            raise RecordNotFoundError()
        return {
            "path": path,
            "latest_version": int(rows[-1]["latest_version"]),
            "versions": [
                {"version": int(row["version"]), "created_at": row["created_at"]}
                for row in rows
            ],
        }

    def delete(self, owner_email: str, path: str) -> None:
        self._authorize(owner_email, path)
        self._vault.require_unlocked()
        if not self._records.delete(owner_email, path):
            raise RecordNotFoundError()
