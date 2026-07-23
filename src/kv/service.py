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
        self, vault_service: VaultService, kv_repository: KvRepository, audit_repository: AuditRepository
    ) -> None:
        self._vault = vault_service
        self._records = kv_repository
        self._audit = audit_repository

    def _authorize(self, requester_email: str, path: str) -> None:
        """Kiểm tra requester có đúng là chủ sở hữu của path hay không.
        Raise PermissionDeniedError cho MỌI trường hợp không khớp -- bao gồm
        cả path sai định dạng -- để không tiết lộ path đó có tồn tại hay
        đúng cấu trúc hay không (tránh làm oracle cho kẻ tấn công dò path)."""
        try:
            path_owner_email = extract_owner_email_from_path(path)
        except ValueError:
            path_owner_email = None

        if path_owner_email is None or path_owner_email != requester_email:
            self._audit.log_denied_access(requester_email, "kv_path", path)
            raise PermissionDeniedError(path)

    @staticmethod
    def _build_aad(owner_email: str, path: str) -> bytes:
        return f"kv:{owner_email}:{path}".encode("utf-8")

    def write(self, owner_email: str, path: str, data: dict[str, Any]) -> dict:
        self._vault.require_unlocked()
        self._authorize(owner_email, path)

        plaintext = json.dumps(data).encode("utf-8")
        dek = self._vault.get_dek()
        blob = encrypt_aes_gcm(dek, plaintext, self._build_aad(owner_email, path))

        return self._records.upsert(
            owner_email=owner_email,
            path=path,
            nonce_b64=encode_b64(blob.nonce),
            ciphertext_b64=encode_b64(blob.ciphertext),
            tag_b64=encode_b64(blob.tag),
        )

    def read(self, owner_email: str, path: str) -> dict[str, Any]:
        self._vault.require_unlocked()
        self._authorize(owner_email, path)

        record = self._records.get(owner_email, path)
        if record is None:
            raise RecordNotFoundError(path)

        try:
            blob = EncryptedBlob(
                nonce=decode_b64(record["nonce_b64"]),
                ciphertext=decode_b64(record["ciphertext_b64"]),
                tag=decode_b64(record["tag_b64"]),
            )
            dek = self._vault.get_dek()
            plaintext = decrypt_aes_gcm(dek, blob, self._build_aad(owner_email, path))
        except (InvalidTag, ValueError) as exc:
            raise RecordTamperedError(path) from exc

        return json.loads(plaintext)

    def delete(self, owner_email: str, path: str) -> None:
        self._vault.require_unlocked()
        self._authorize(owner_email, path)

        deleted = self._records.delete(owner_email, path)
        if not deleted:
            raise RecordNotFoundError(path)