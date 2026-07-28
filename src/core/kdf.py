from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from src.core import settings


@dataclass(frozen=True)
class KDFParameters:
    """Argon2id cost parameters, persisted alongside the wrapped DEK.

    They are stored in the Vault config rather than hard-coded so the cost can
    be raised later without making an existing Vault un-unlockable: unlock
    always replays the parameters the DEK was originally wrapped with.
    """

    time_cost: int = settings.DEFAULT_KDF_TIME_COST
    memory_cost: int = settings.DEFAULT_KDF_MEMORY_COST
    parallelism: int = settings.DEFAULT_KDF_PARALLELISM
    hash_len: int = settings.DEFAULT_KDF_HASH_LENGTH


DEFAULT_KDF_PARAMETERS = KDFParameters()


def current_parameters() -> KDFParameters:
    """Parameters used for a new initialization (see src/core/settings.py)."""
    configured = settings.load()
    return KDFParameters(
        time_cost=configured.kdf_time_cost,
        memory_cost=configured.kdf_memory_cost,
        parallelism=configured.kdf_parallelism,
        hash_len=configured.kdf_hash_length,
    )


def derive_wrapping_key(
    master_passphrase: str,
    salt: bytes,
    parameters: KDFParameters = DEFAULT_KDF_PARAMETERS,
) -> bytes:
    """Argon2id: Master Passphrase + salt -> 32-byte key that wraps the DEK.

    Argon2id is memory-hard, which is what makes offline guessing against the
    stored `encrypted_dek_b64` expensive. The derived key is returned to the
    caller and is never written to disk.
    """
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
