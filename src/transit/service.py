import hashlib
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.crypto import EncryptedBlob, decrypt_aes_gcm, encrypt_aes_gcm
from src.core.encoding import decode_b64, encode_b64
from src.core.vault import VaultService
from src.kv.audit_repository import AuditRepository
from src.transit.ciphertext import KEY_NAME_PATTERN, format_ciphertext, parse_ciphertext
from src.transit.exceptions import (
    InvalidBase64PayloadError,
    InvalidDigestLengthError,
    InvalidKeyUsageError,
    InvalidKeyNameError,
    InvalidMessageTypeError,
    InvalidSigningAlgorithmError,
    KeyRevokedError,
    KeyUnavailableError,
    TransitTamperedError,
)
from src.transit.repository import NamedKeyRepository


ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
SIGN_VERIFY = "SIGN_VERIFY"
ED25519 = "ED25519"
RAW = "RAW"
DIGEST = "DIGEST"
SHA256_DIGEST_LENGTH = 32


class TransitService:
    def __init__(
        self,
        vault: VaultService,
        keys: NamedKeyRepository,
        audit: AuditRepository,
    ) -> None:
        self._vault = vault
        self._keys = keys
        self._audit = audit

    @staticmethod
    def validate_key_name(key_name: str) -> None:
        if not isinstance(key_name, str) or not KEY_NAME_PATTERN.fullmatch(key_name):
            raise InvalidKeyNameError()

    @staticmethod
    def _key_aad(
        owner_email: str,
        key_name: str,
        key_usage: str,
        signing_algorithm: str | None,
    ) -> bytes:
        return (
            f"transit-key:{owner_email}:{key_name}:{key_usage}:{signing_algorithm or '-'}"
        ).encode("utf-8")

    @staticmethod
    def _data_aad(owner_email: str, key_name: str) -> bytes:
        return f"transit-data:{owner_email}:{key_name}".encode("utf-8")

    def _owned_key(self, owner_email: str, key_name: str):
        self.validate_key_name(key_name)
        row = self._keys.get_owned(owner_email, key_name)
        if row is None:
            self._audit.log_denied_access(owner_email, "named_key", key_name)
            # The same response is used for missing and foreign keys.
            raise KeyUnavailableError()
        return row

    @staticmethod
    def _require_active(row) -> None:
        if row["revoked_at"] is not None:
            raise KeyRevokedError()

    def _unwrap(self, row) -> bytes:
        try:
            return decrypt_aes_gcm(
                self._vault.get_dek(),
                EncryptedBlob(
                    nonce=decode_b64(row["nonce_b64"]),
                    ciphertext=decode_b64(row["encrypted_key_material_b64"]),
                    tag=decode_b64(row["tag_b64"]),
                ),
                self._key_aad(
                    row["owner_email"],
                    row["key_name"],
                    row["key_usage"],
                    row["signing_algorithm"],
                ),
            )
        except (InvalidTag, ValueError) as exc:
            raise TransitTamperedError() from exc

    def create_key(self, owner_email: str, key_name: str) -> dict:
        self.validate_key_name(key_name)
        self._vault.require_unlocked()
        key_material = AESGCM.generate_key(bit_length=256)
        blob = encrypt_aes_gcm(
            self._vault.get_dek(),
            key_material,
            self._key_aad(owner_email, key_name, ENCRYPT_DECRYPT, None),
        )
        row = self._keys.create(
            owner_email,
            key_name,
            ENCRYPT_DECRYPT,
            None,
            encode_b64(blob.nonce),
            encode_b64(blob.ciphertext),
            encode_b64(blob.tag),
            None,
        )
        return self._metadata(row)

    def create_signing_key(
        self, owner_email: str, key_name: str, signing_algorithm: str
    ) -> dict:
        self.validate_key_name(key_name)
        normalized = signing_algorithm.upper()
        if normalized != ED25519:
            raise InvalidSigningAlgorithmError()
        self._vault.require_unlocked()
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        blob = encrypt_aes_gcm(
            self._vault.get_dek(),
            private_bytes,
            self._key_aad(owner_email, key_name, SIGN_VERIFY, ED25519),
        )
        row = self._keys.create(
            owner_email,
            key_name,
            SIGN_VERIFY,
            ED25519,
            encode_b64(blob.nonce),
            encode_b64(blob.ciphertext),
            encode_b64(blob.tag),
            encode_b64(public_bytes),
        )
        return self._metadata(row)

    def list_keys(self, owner_email: str) -> list[dict]:
        return [self._metadata(row) for row in self._keys.list_owned(owner_email)]

    def revoke_key(self, owner_email: str, key_name: str) -> dict:
        row = self._owned_key(owner_email, key_name)
        self._require_active(row)
        self._vault.require_unlocked()
        if not self._keys.revoke_owned(owner_email, key_name):
            raise KeyRevokedError()
        updated = self._keys.get_owned(owner_email, key_name)
        return self._metadata(updated)

    def encrypt(self, owner_email: str, key_name: str, plaintext_b64: str) -> dict:
        row = self._owned_key(owner_email, key_name)
        self._require_active(row)
        if row["key_usage"] != ENCRYPT_DECRYPT:
            raise InvalidKeyUsageError()
        self._vault.require_unlocked()
        plaintext = self._decode_payload(plaintext_b64)
        key_material = self._unwrap(row)
        if len(key_material) != 32:
            raise TransitTamperedError()
        blob = encrypt_aes_gcm(
            key_material,
            plaintext,
            self._data_aad(owner_email, key_name),
        )
        return {"key_name": key_name, "ciphertext": format_ciphertext(key_name, blob)}

    def decrypt(self, owner_email: str, ciphertext: str) -> dict:
        parsed = parse_ciphertext(ciphertext)
        row = self._owned_key(owner_email, parsed.key_name)
        self._require_active(row)
        if row["key_usage"] != ENCRYPT_DECRYPT:
            raise InvalidKeyUsageError()
        self._vault.require_unlocked()
        key_material = self._unwrap(row)
        try:
            plaintext = decrypt_aes_gcm(
                key_material,
                parsed.blob,
                self._data_aad(owner_email, parsed.key_name),
            )
        except (InvalidTag, ValueError) as exc:
            raise TransitTamperedError() from exc
        return {"key_name": parsed.key_name, "plaintext_b64": encode_b64(plaintext)}

    def sign(
        self,
        owner_email: str,
        key_name: str,
        message_b64: str,
        message_type: str,
        signing_algorithm: str,
    ) -> dict:
        row = self._owned_key(owner_email, key_name)
        self._require_active(row)
        if row["key_usage"] != SIGN_VERIFY:
            raise InvalidKeyUsageError()
        self._validate_algorithm(row, signing_algorithm)
        self._vault.require_unlocked()
        digest = self._message_digest(message_b64, message_type)
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(self._unwrap(row))
        except ValueError as exc:
            raise TransitTamperedError() from exc
        signature = private_key.sign(digest)
        return {
            "key_name": key_name,
            "signing_algorithm": row["signing_algorithm"],
            "signature_b64": encode_b64(signature),
        }

    def verify(
        self,
        owner_email: str,
        key_name: str,
        message_b64: str,
        message_type: str,
        signature_b64: str,
        signing_algorithm: str,
    ) -> dict:
        row = self._owned_key(owner_email, key_name)
        self._require_active(row)
        if row["key_usage"] != SIGN_VERIFY:
            raise InvalidKeyUsageError()
        self._validate_algorithm(row, signing_algorithm)
        self._vault.require_unlocked()
        digest = self._message_digest(message_b64, message_type)
        try:
            signature = decode_b64(signature_b64)
            public_bytes = decode_b64(row["public_key_b64"])
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, digest)
            valid = True
        except (ValueError, InvalidSignature, TypeError):
            valid = False
        return {
            "key_name": key_name,
            "signing_algorithm": row["signing_algorithm"],
            "signature_valid": valid,
        }

    @staticmethod
    def _metadata(row) -> dict:
        return {
            "key_name": row["key_name"],
            "key_usage": row["key_usage"],
            "signing_algorithm": row["signing_algorithm"],
            "created_at": row["created_at"],
            "revoked": row["revoked_at"] is not None,
        }

    @staticmethod
    def _decode_payload(value: str) -> bytes:
        try:
            return decode_b64(value)
        except (ValueError, UnicodeEncodeError) as exc:
            raise InvalidBase64PayloadError() from exc

    def _message_digest(self, message_b64: str, message_type: str) -> bytes:
        message = self._decode_payload(message_b64)
        normalized = message_type.upper()
        if normalized == RAW:
            return hashlib.sha256(message).digest()
        if normalized == DIGEST:
            if len(message) != SHA256_DIGEST_LENGTH:
                raise InvalidDigestLengthError()
            return message
        raise InvalidMessageTypeError()

    @staticmethod
    def _validate_algorithm(row, signing_algorithm: str) -> None:
        if signing_algorithm.upper() != row["signing_algorithm"]:
            raise InvalidSigningAlgorithmError()
