import hashlib
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.audit.repository import AuditRepository
from src.core.crypto import EncryptedBlob, decrypt_aes_gcm, encrypt_aes_gcm
from src.core.encoding import decode_b64, encode_b64
from src.core.vault import VaultService
from src.transit.ciphertext import KEY_NAME_PATTERN, format_ciphertext, parse_ciphertext
from src.transit.exceptions import (
    InvalidBase64PayloadError,
    InvalidDigestLengthError,
    InvalidKeyUsageError,
    InvalidKeyNameError,
    InvalidMessageTypeError,
    InvalidSigningAlgorithmError,
    KeyUnavailableError,
    KeyVersionUnavailableError,
    TransitTamperedError,
)
from src.transit.repository import NamedKeyRepository


ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
SIGN_VERIFY = "SIGN_VERIFY"
ED25519 = "ED25519"
RAW = "RAW"
DIGEST = "DIGEST"
SHA256_DIGEST_LENGTH = 32
AES_KEY_LENGTH = 32


class TransitService:
    """Feature 2: encryption and signing as a service.

    Key material is generated server-side, wrapped with the DEK before it
    touches disk, and unwrapped only for the duration of one operation. No code
    path returns key material to a client.

    Section IV extra: named keys are versioned. `encrypt` and `sign` always use
    the newest version; `decrypt` uses the version named by the ciphertext, so
    data encrypted before a rotation still decrypts.
    """

    def __init__(
        self,
        vault: VaultService,
        keys: NamedKeyRepository,
        audit: AuditRepository,
    ) -> None:
        self._vault = vault
        self._keys = keys
        self._audit = audit

    # ------------------------------------------------------------------ helpers

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
        version: int,
    ) -> bytes:
        """Associated data for wrapped key material.

        Binding owner, name, usage, algorithm and version means a row cannot be
        edited or copied onto another key without breaking unwrap.
        """
        return (
            f"transit-key:{owner_email}:{key_name}:{key_usage}:"
            f"{signing_algorithm or '-'}:v{version}"
        ).encode("utf-8")

    @staticmethod
    def _data_aad(owner_email: str, key_name: str, version: int) -> bytes:
        return f"transit-data:{owner_email}:{key_name}:v{version}".encode("utf-8")

    def _owned_key(self, owner_email: str, key_name: str):
        """Feature 2.3: resolve a key only if the caller owns it.

        Missing keys and keys owned by somebody else produce the same error, so
        a caller cannot use the response to discover which key names exist.
        """
        self.validate_key_name(key_name)
        row = self._keys.get_owned(owner_email, key_name)
        if row is None:
            self._audit.log_denied_access(owner_email, "named_key", key_name)
            raise KeyUnavailableError()
        return row

    def _key_version(self, key_row, version: int):
        version_row = self._keys.get_version(int(key_row["id"]), version)
        if version_row is None:
            raise KeyVersionUnavailableError()
        return version_row

    def _unwrap(self, key_row, version_row) -> bytes:
        """Decrypt key material with the in-memory DEK. Never leaves this class."""
        try:
            return decrypt_aes_gcm(
                self._vault.get_dek(),
                EncryptedBlob(
                    nonce=decode_b64(version_row["nonce_b64"]),
                    ciphertext=decode_b64(version_row["encrypted_key_material_b64"]),
                    tag=decode_b64(version_row["tag_b64"]),
                ),
                self._key_aad(
                    key_row["owner_email"],
                    key_row["key_name"],
                    key_row["key_usage"],
                    key_row["signing_algorithm"],
                    int(version_row["version"]),
                ),
            )
        except (InvalidTag, ValueError) as exc:
            raise TransitTamperedError() from exc

    def _wrap_aes(self, owner_email: str, key_name: str):
        def wrap(version: int) -> tuple[str, str, str, Optional[str]]:
            material = AESGCM.generate_key(bit_length=256)
            blob = encrypt_aes_gcm(
                self._vault.get_dek(),
                material,
                self._key_aad(owner_email, key_name, ENCRYPT_DECRYPT, None, version),
            )
            return (
                encode_b64(blob.nonce),
                encode_b64(blob.ciphertext),
                encode_b64(blob.tag),
                None,
            )

        return wrap

    def _wrap_ed25519(self, owner_email: str, key_name: str):
        def wrap(version: int) -> tuple[str, str, str, Optional[str]]:
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
                self._key_aad(owner_email, key_name, SIGN_VERIFY, ED25519, version),
            )
            # Only the private half is wrapped; the public half is not secret,
            # but it is still never returned by any endpoint.
            return (
                encode_b64(blob.nonce),
                encode_b64(blob.ciphertext),
                encode_b64(blob.tag),
                encode_b64(public_bytes),
            )

        return wrap

    # ------------------------------------------------------------- key lifecycle

    def create_key(self, owner_email: str, key_name: str) -> dict:
        """2.1 — create an AES-256 key with key_usage ENCRYPT_DECRYPT.

        A name already owned by the caller is rejected (KEY_ALREADY_EXISTS)
        rather than silently overwritten; overwriting would destroy the key that
        existing ciphertext depends on. Rotation is the supported way to move to
        new key material under the same name.
        """
        self.validate_key_name(key_name)
        self._vault.require_unlocked()
        row = self._keys.create(
            owner_email, key_name, ENCRYPT_DECRYPT, None, self._wrap_aes(owner_email, key_name)
        )
        return self._metadata(row)

    def create_signing_key(
        self, owner_email: str, key_name: str, signing_algorithm: str
    ) -> dict:
        """2.4 — create an ED25519 key pair with key_usage SIGN_VERIFY."""
        self.validate_key_name(key_name)
        normalized = signing_algorithm.upper()
        if normalized != ED25519:
            raise InvalidSigningAlgorithmError()
        self._vault.require_unlocked()
        row = self._keys.create(
            owner_email,
            key_name,
            SIGN_VERIFY,
            ED25519,
            self._wrap_ed25519(owner_email, key_name),
        )
        return self._metadata(row)

    def rotate_key(self, owner_email: str, key_name: str) -> dict:
        """Section IV — add a new version of an existing named key.

        New encrypt/sign operations use the new version immediately; earlier
        versions stay on disk so old ciphertext and signatures remain usable.
        """
        key_row = self._owned_key(owner_email, key_name)
        self._vault.require_unlocked()
        wrap = (
            self._wrap_aes(owner_email, key_name)
            if key_row["key_usage"] == ENCRYPT_DECRYPT
            else self._wrap_ed25519(owner_email, key_name)
        )
        rotated = self._keys.rotate(owner_email, key_name, wrap)
        if rotated is None:
            raise KeyUnavailableError()
        return self._metadata(rotated)

    def list_keys(self, owner_email: str) -> list[dict]:
        """2.1 — names, usage and version metadata only. Never key material."""
        self._vault.require_unlocked()
        return [self._metadata(row) for row in self._keys.list_owned(owner_email)]

    def delete_key(self, owner_email: str, key_name: str) -> dict:
        """2.1 — revoke_key: permanently delete the key and all its versions."""
        self._owned_key(owner_email, key_name)
        self._vault.require_unlocked()
        if not self._keys.delete_owned(owner_email, key_name):
            raise KeyUnavailableError()
        return {"key_name": key_name, "deleted": True}

    # ------------------------------------------------------------ encrypt/decrypt

    def encrypt(self, owner_email: str, key_name: str, plaintext_b64: str) -> dict:
        key_row = self._owned_key(owner_email, key_name)
        if key_row["key_usage"] != ENCRYPT_DECRYPT:
            # Mirrors AWS KMS InvalidKeyUsageException.
            raise InvalidKeyUsageError()
        self._vault.require_unlocked()
        plaintext = self._decode_payload(plaintext_b64)

        version = int(key_row["latest_version"])
        version_row = self._key_version(key_row, version)
        material = self._unwrap(key_row, version_row)
        if len(material) != AES_KEY_LENGTH:
            raise TransitTamperedError()

        blob = encrypt_aes_gcm(
            material, plaintext, self._data_aad(owner_email, key_name, version)
        )
        return {
            "key_name": key_name,
            "key_version": version,
            "ciphertext": format_ciphertext(key_name, version, blob),
        }

    def decrypt(self, owner_email: str, ciphertext: str) -> dict:
        # Framing is validated first so truncated input never reaches a key.
        parsed = parse_ciphertext(ciphertext)
        key_row = self._owned_key(owner_email, parsed.key_name)
        if key_row["key_usage"] != ENCRYPT_DECRYPT:
            raise InvalidKeyUsageError()
        self._vault.require_unlocked()

        version_row = self._key_version(key_row, parsed.key_version)
        material = self._unwrap(key_row, version_row)
        try:
            plaintext = decrypt_aes_gcm(
                material,
                parsed.blob,
                self._data_aad(owner_email, parsed.key_name, parsed.key_version),
            )
        except (InvalidTag, ValueError) as exc:
            raise TransitTamperedError() from exc
        return {
            "key_name": parsed.key_name,
            "key_version": parsed.key_version,
            "plaintext_b64": encode_b64(plaintext),
        }

    # ---------------------------------------------------------------- sign/verify

    def sign(
        self,
        owner_email: str,
        key_name: str,
        message_b64: str,
        message_type: str,
        signing_algorithm: str,
    ) -> dict:
        key_row = self._owned_key(owner_email, key_name)
        if key_row["key_usage"] != SIGN_VERIFY:
            raise InvalidKeyUsageError()
        self._validate_algorithm(key_row, signing_algorithm)
        self._vault.require_unlocked()
        digest = self._message_digest(message_b64, message_type)

        version = int(key_row["latest_version"])
        version_row = self._key_version(key_row, version)
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(
                self._unwrap(key_row, version_row)
            )
        except ValueError as exc:
            raise TransitTamperedError() from exc

        signature = private_key.sign(digest)
        return {
            "key_name": key_name,
            "key_version": version,
            "signing_algorithm": key_row["signing_algorithm"],
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
        key_version: Optional[int] = None,
    ) -> dict:
        """2.4 — structured verification result, mirroring AWS KMS Verify.

        With rotation enabled a signature does not say which version produced
        it, so unless the caller pins `key_version` every version of the key is
        tried, newest first. A signature made with a different named key still
        fails against all of them.
        """
        key_row = self._owned_key(owner_email, key_name)
        if key_row["key_usage"] != SIGN_VERIFY:
            raise InvalidKeyUsageError()
        self._validate_algorithm(key_row, signing_algorithm)
        self._vault.require_unlocked()
        digest = self._message_digest(message_b64, message_type)

        if key_version is not None:
            candidates = [self._key_version(key_row, key_version)]
        else:
            candidates = [
                self._key_version(key_row, int(row["version"]))
                for row in reversed(self._keys.list_versions(int(key_row["id"])))
            ]

        try:
            signature = decode_b64(signature_b64)
        except (ValueError, UnicodeEncodeError):
            # A malformed signature is an invalid signature, not a crash.
            signature = None

        matched_version = None
        if signature is not None:
            for version_row in candidates:
                public_b64 = version_row["public_key_b64"]
                if not public_b64:
                    continue
                try:
                    Ed25519PublicKey.from_public_bytes(decode_b64(public_b64)).verify(
                        signature, digest
                    )
                except (ValueError, InvalidSignature, TypeError):
                    continue
                matched_version = int(version_row["version"])
                break

        return {
            "key_name": key_name,
            "key_version": matched_version,
            "signing_algorithm": key_row["signing_algorithm"],
            "signature_valid": matched_version is not None,
        }

    # ----------------------------------------------------------------- utilities

    def _metadata(self, row) -> dict:
        """Everything an owner may see about a key. Deliberately excludes any
        column holding key material or the public key bytes."""
        return {
            "key_name": row["key_name"],
            "key_usage": row["key_usage"],
            "signing_algorithm": row["signing_algorithm"],
            "latest_version": int(row["latest_version"]),
            "versions": [
                int(item["version"]) for item in self._keys.list_versions(int(row["id"]))
            ],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _decode_payload(value: str) -> bytes:
        try:
            return decode_b64(value)
        except (ValueError, UnicodeEncodeError) as exc:
            raise InvalidBase64PayloadError() from exc

    def _message_digest(self, message_b64: str, message_type: str) -> bytes:
        """RAW hashes with SHA-256 first; DIGEST must already be a 32-byte hash."""
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
