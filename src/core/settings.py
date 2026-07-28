"""Runtime configuration read from environment variables.

Everything here has a secure default, so Mini Vault runs correctly with no
environment at all. The variables exist for two reasons:

* deployments differ (where the database lives, how long a session lasts);
* Argon2 cost parameters are a deliberate trade-off. Production wants them
  high; the test suite runs hundreds of derivations and would otherwise spend
  minutes on key stretching alone.

Secrets are NOT configured here. The Master Passphrase is never read from the
environment: it is typed in at init/unlock and only ever exists in memory, which
is the whole point of section 0.1.

See `.env.example` for the documented list.
"""

import os
from dataclasses import dataclass
from pathlib import Path


PREFIX = "MINIVAULT_"

# Interactive Argon2id defaults, in the range RFC 9106 recommends for
# password-based key derivation on general purpose hardware.
DEFAULT_KDF_TIME_COST = 3
DEFAULT_KDF_MEMORY_COST = 65536  # KiB
DEFAULT_KDF_PARALLELISM = 4
DEFAULT_KDF_HASH_LENGTH = 32

DEFAULT_SESSION_TTL_MINUTES = 30
DEFAULT_LOCKOUT_MINUTES = 5
DEFAULT_MAX_FAILED_ATTEMPTS = 5

DEFAULT_CONFIG_PATH = "data/vault_config.json"
DEFAULT_DATABASE_PATH = "data/mini_vault.db"


def _int(name: str, default: int, minimum: int = 1) -> int:
    """Read a positive integer, ignoring values that would weaken safety limits."""
    raw = os.environ.get(PREFIX + name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= minimum else default


def _path(name: str, default: str) -> Path:
    return Path(os.environ.get(PREFIX + name, default))


@dataclass(frozen=True)
class Settings:
    kdf_time_cost: int
    kdf_memory_cost: int
    kdf_parallelism: int
    kdf_hash_length: int
    password_time_cost: int
    password_memory_cost: int
    password_parallelism: int
    session_ttl_minutes: int
    lockout_minutes: int
    max_failed_attempts: int
    config_path: Path
    database_path: Path


def load() -> Settings:
    """Read settings fresh on every call.

    Deliberately not cached at import time so a process (or a test) can adjust
    the environment before the first use.
    """
    kdf_time = _int("KDF_TIME_COST", DEFAULT_KDF_TIME_COST)
    kdf_memory = _int("KDF_MEMORY_COST", DEFAULT_KDF_MEMORY_COST, minimum=8)
    kdf_parallelism = _int("KDF_PARALLELISM", DEFAULT_KDF_PARALLELISM)
    return Settings(
        kdf_time_cost=kdf_time,
        kdf_memory_cost=kdf_memory,
        kdf_parallelism=kdf_parallelism,
        kdf_hash_length=_int("KDF_HASH_LENGTH", DEFAULT_KDF_HASH_LENGTH, minimum=32),
        # Password hashing defaults to the same cost as the KDF unless it is
        # tuned separately.
        password_time_cost=_int("PASSWORD_TIME_COST", kdf_time),
        password_memory_cost=_int("PASSWORD_MEMORY_COST", kdf_memory, minimum=8),
        password_parallelism=_int("PASSWORD_PARALLELISM", kdf_parallelism),
        session_ttl_minutes=_int("SESSION_TTL_MINUTES", DEFAULT_SESSION_TTL_MINUTES),
        lockout_minutes=_int("LOCKOUT_MINUTES", DEFAULT_LOCKOUT_MINUTES),
        max_failed_attempts=_int("MAX_FAILED_ATTEMPTS", DEFAULT_MAX_FAILED_ATTEMPTS),
        config_path=_path("CONFIG_PATH", DEFAULT_CONFIG_PATH),
        database_path=_path("DATABASE_PATH", DEFAULT_DATABASE_PATH),
    )
