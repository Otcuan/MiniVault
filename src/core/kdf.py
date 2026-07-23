from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw


@dataclass(frozen=True)
class KDFParameters:
    """Tham số Argon2id được lưu cùng cấu hình để unlock có thể tái tạo khóa."""

    time_cost: int = 3
    memory_cost: int = 65536  # KiB = 64 MiB
    parallelism: int = 4
    hash_len: int = 32  # 32 bytes = 256 bits


DEFAULT_KDF_PARAMETERS = KDFParameters()


def derive_wrapping_key(
    master_passphrase: str,
    salt: bytes,
    parameters: KDFParameters = DEFAULT_KDF_PARAMETERS,
) -> bytes:
    """Dẫn xuất wrapping key 32 byte từ Master Passphrase bằng Argon2id."""

    if not isinstance(master_passphrase, str):
        raise TypeError("Master Passphrase must be a string")
    if not master_passphrase:
        raise ValueError("Master Passphrase cannot be empty")
    if len(salt) < 16:
        raise ValueError("KDF salt must contain at least 16 bytes")

    return hash_secret_raw(
        secret=master_passphrase.encode("utf-8"),
        salt=salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_cost,
        parallelism=parameters.parallelism,
        hash_len=parameters.hash_len,
        type=Type.ID,
    )
