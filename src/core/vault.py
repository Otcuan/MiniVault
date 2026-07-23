import secrets
from typing import Any

from cryptography.exceptions import InvalidTag

from src.core.crypto import EncryptedBlob, decrypt_aes_gcm, encrypt_aes_gcm, generate_dek
from src.core.encoding import decode_b64, encode_b64
from src.core.exceptions import (
    InvalidMasterPassphraseError,
    InvalidMasterPassphrasePolicyError,
    VaultAlreadyInitializedError,
    VaultConfigCorruptedError,
    VaultNotInitializedError,
)
from src.core.kdf import KDFParameters, derive_wrapping_key
from src.core.state import VaultState
from src.storage.config_store import JsonConfigStore


CONFIG_VERSION = 1
DEK_WRAP_AAD = b"mini-vault:dek-wrap:v1"


class VaultService:
    """Điều phối init, unlock, lock và cung cấp DEK cho service nội bộ."""

    def __init__(self, config_store: JsonConfigStore, state: VaultState) -> None:
        self.config_store = config_store
        self.state = state

    def is_initialized(self) -> bool:
        return self.config_store.exists()

    def initialize(self, master_passphrase: str) -> dict[str, Any]:
        if self.is_initialized():
            raise VaultAlreadyInitializedError()

        self._validate_master_passphrase(master_passphrase)

        salt = secrets.token_bytes(16)
        parameters = KDFParameters()
        wrapping_key = derive_wrapping_key(master_passphrase, salt, parameters)
        dek = generate_dek()

        encrypted_dek = encrypt_aes_gcm(
            key=wrapping_key,
            plaintext=dek,
            associated_data=DEK_WRAP_AAD,
        )

        config = {
            "version": CONFIG_VERSION,
            "status": "locked",
            "kdf": "argon2id",
            "kdf_salt_b64": encode_b64(salt),
            "kdf_parameters": {
                "time_cost": parameters.time_cost,
                "memory_cost": parameters.memory_cost,
                "parallelism": parameters.parallelism,
                "hash_len": parameters.hash_len,
            },
            "dek_nonce_b64": encode_b64(encrypted_dek.nonce),
            "encrypted_dek_b64": encode_b64(encrypted_dek.ciphertext),
            "dek_tag_b64": encode_b64(encrypted_dek.tag),
        }

        self.config_store.save_atomic(config)
        self.state.lock()  # init xong vẫn locked theo thiết kế của nhóm
        return self.status()

    def unlock(self, master_passphrase: str) -> dict[str, Any]:
        if not self.is_initialized():
            raise VaultNotInitializedError()

        self.state.lock()  # thử unlock thất bại thì Vault chắc chắn vẫn khóa
        config = self._load_and_validate_config()

        try:
            salt = decode_b64(config["kdf_salt_b64"])
            parameter_data = config["kdf_parameters"]
            parameters = KDFParameters(
                time_cost=int(parameter_data["time_cost"]),
                memory_cost=int(parameter_data["memory_cost"]),
                parallelism=int(parameter_data["parallelism"]),
                hash_len=int(parameter_data["hash_len"]),
            )

            wrapping_key = derive_wrapping_key(master_passphrase, salt, parameters)
            encrypted_dek = EncryptedBlob(
                nonce=decode_b64(config["dek_nonce_b64"]),
                ciphertext=decode_b64(config["encrypted_dek_b64"]),
                tag=decode_b64(config["dek_tag_b64"]),
            )
            dek = decrypt_aes_gcm(
                key=wrapping_key,
                blob=encrypted_dek,
                associated_data=DEK_WRAP_AAD,
            )
        except InvalidTag as exc:
            # Không tiết lộ là sai passphrase hay tag/ciphertext bị sửa.
            raise InvalidMasterPassphraseError() from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultConfigCorruptedError() from exc

        if len(dek) != 32:
            raise VaultConfigCorruptedError()

        self.state.set_dek(dek)
        return self.status()

    def lock(self) -> dict[str, Any]:
        self.state.lock()
        return self.status()

    def require_unlocked(self) -> None:
        self.state.get_dek()

    def get_dek(self) -> bytes:
        """Chỉ dùng trong service nội bộ; không đưa giá trị này vào API response."""
        return self.state.get_dek()

    def status(self) -> dict[str, Any]:
        if not self.is_initialized():
            return {"initialized": False, "status": "not_initialized"}
        return {
            "initialized": True,
            "status": "unlocked" if self.state.is_unlocked else "locked",
        }

    def _load_and_validate_config(self) -> dict[str, Any]:
        config = self.config_store.load()
        required_fields = {
            "version",
            "status",
            "kdf",
            "kdf_salt_b64",
            "kdf_parameters",
            "dek_nonce_b64",
            "encrypted_dek_b64",
            "dek_tag_b64",
        }

        if not required_fields.issubset(config.keys()):
            raise VaultConfigCorruptedError()
        if config["version"] != CONFIG_VERSION:
            raise VaultConfigCorruptedError()
        if config["kdf"] != "argon2id":
            raise VaultConfigCorruptedError()
        return config

    @staticmethod
    def _validate_master_passphrase(master_passphrase: str) -> None:
        if not isinstance(master_passphrase, str):
            raise InvalidMasterPassphrasePolicyError()
        if len(master_passphrase) < 12 or master_passphrase.isspace():
            raise InvalidMasterPassphrasePolicyError()
