import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from src.core import settings


SESSION_TOKEN_BYTES = 32


def generate_session_token() -> str:
    """256 bits from the OS CSPRNG. Returned once, never stored in the clear."""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Only the hash reaches the database.

    A plain SHA-256 is the right tool here, unlike for passwords: the token is
    already a full-entropy random value, so there is nothing to brute-force and
    no reason to put a slow KDF on every authenticated request.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def compute_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(
        minutes=settings.load().session_ttl_minutes
    )


def is_expired(expires_at: datetime) -> bool:
    return datetime.now(timezone.utc) >= expires_at


def compute_lockout_until() -> datetime:
    return datetime.now(timezone.utc) + timedelta(
        minutes=settings.load().lockout_minutes
    )
