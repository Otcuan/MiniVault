import json
from typing import Any

from cryptography.exceptions import InvalidTag

from src.core.crypto import EncryptedBlob, decrypt_aes_gcm, encrypt_aes_gcm
from src.core.encoding import decode_b64, encode_b64
from src.core.vault import VaultService
from src.kv.audit_repository import AuditRepository
from src.kv.exceptions import PermissionDeniedError, RecordNotFoundError, RecordTamperedError
from src.kv.paths import extract_owner_email_from_path
from src.kv.repository import KvRepository


class KvService:
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
        try:
            path_owner = extract_owner_email_from_path(path)
        except ValueError:
            path_owner = None
        if path_owner != requester_email:
            self._audit.log_denied_access(requester_email, "kv_path", path)
            raise PermissionDeniedError()

    @staticmethod
    def _aad(owner_email: str, path: str) -> bytes:
        return f"kv:{owner_email}:{path}".encode("utf-8")

    def write(self, owner_email: str, path: str, data: dict[str, Any]) -> dict:
        # Ownership is checked before Vault state to avoid a state oracle.
        self._authorize(owner_email, path)
        self._vault.require_unlocked()
        plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        blob = encrypt_aes_gcm(self._vault.get_dek(), plaintext, self._aad(owner_email, path))
        return self._records.upsert(
            owner_email,
            path,
            encode_b64(blob.nonce),
            encode_b64(blob.ciphertext),
            encode_b64(blob.tag),
        )

    def read(self, owner_email: str, path: str) -> dict[str, Any]:
        self._authorize(owner_email, path)
        self._vault.require_unlocked()
        record = self._records.get(owner_email, path)
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
                self._aad(owner_email, path),
            )
            decoded = json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RecordTamperedError() from exc
        if not isinstance(decoded, dict):
            raise RecordTamperedError()
        return decoded

    def delete(self, owner_email: str, path: str) -> None:
        self._authorize(owner_email, path)
        self._vault.require_unlocked()
        if not self._records.delete(owner_email, path):
            raise RecordNotFoundError()
