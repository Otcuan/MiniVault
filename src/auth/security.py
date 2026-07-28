from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

from src.core import settings


def _hasher() -> PasswordHasher:
    """Build a hasher from the current settings.

    Argon2 encodes its parameters inside the hash string, so verification keeps
    working against hashes produced with a different cost. That is what allows
    the cost to be raised later without invalidating existing accounts.
    """
    configured = settings.load()
    return PasswordHasher(
        time_cost=configured.password_time_cost,
        memory_cost=configured.password_memory_cost,
        parallelism=configured.password_parallelism,
    )


def hash_password(password: str) -> str:
    """Argon2id with a per-hash random salt. Never a bare SHA (section 0.2)."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    return _hasher().hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verification failures are values, not exceptions, so callers cannot
    accidentally leak the reason a login failed."""
    try:
        _hasher().verify(password_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
