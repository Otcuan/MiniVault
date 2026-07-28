from datetime import datetime, timezone

from src.auth.exceptions import (
    AccountLockedError,
    InvalidCredentialsError,
    PassphraseMismatchError,
    WeakPassphraseError,
)
from src.auth.repository import UserRepository
from src.auth.security import hash_password, verify_password
from src.auth.session import compute_expiry, compute_lockout_until, generate_session_token, hash_token
from src.auth.session_repository import SessionRepository
from src.core import settings
from src.core.passphrase import evaluate as evaluate_passphrase


_dummy_password_hash: str | None = None


def _dummy_hash() -> str:
    """A real Argon2 hash to verify against when the account does not exist.

    Without it, "unknown email" would return noticeably faster than "wrong
    passphrase" and the response time alone would reveal which emails are
    registered. Computed once, lazily, so import time stays cheap.
    """
    global _dummy_password_hash
    if _dummy_password_hash is None:
        _dummy_password_hash = hash_password("timing-attack-mitigation-placeholder")
    return _dummy_password_hash


class AuthService:
    def __init__(self, users: UserRepository, sessions: SessionRepository) -> None:
        self._users = users
        self._sessions = sessions

    def register(self, email: str, passphrase: str, confirm_passphrase: str) -> dict:
        if passphrase != confirm_passphrase:
            raise PassphraseMismatchError()
        # Section 0.2 step 1: strength check before the account is created.
        issue = evaluate_passphrase(passphrase)
        if issue is not None:
            raise WeakPassphraseError(issue.code)
        # Argon2id, never a bare SHA. The plaintext passphrase is not stored,
        # logged, or echoed back in the response.
        user = self._users.create(email, hash_password(passphrase))
        return {"email": user["email"], "created_at": user["created_at"]}

    def login(self, email: str, passphrase: str) -> dict:
        user = self._users.get_by_email(email)
        if user is None:
            # Same work as a real failure, so timing does not reveal existence.
            verify_password(passphrase, _dummy_hash())
            raise InvalidCredentialsError()

        if user["locked_until"] is not None:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now(timezone.utc) < locked_until:
                raise AccountLockedError()
            # Expired lockout starts a fresh failure window.
            self._users.reset_login_failures(user["id"])
            user = self._users.get_by_email(email)
            if user is None:
                raise InvalidCredentialsError()

        if not verify_password(passphrase, user["password_hash"]):
            self._register_failed_attempt(user)
            raise InvalidCredentialsError()

        self._users.reset_login_failures(user["id"])
        token = generate_session_token()
        expires_at = compute_expiry()
        self._sessions.create(user["id"], hash_token(token), expires_at.isoformat())
        return {"token": token, "expires_at": expires_at.isoformat()}

    def logout(self, token: str) -> None:
        self._sessions.revoke(hash_token(token))

    def _register_failed_attempt(self, user) -> None:
        """Section 0.2 step 4: lock the account after N consecutive failures."""
        new_count = int(user["failed_attempts"]) + 1
        locked_until = (
            compute_lockout_until().isoformat()
            if new_count >= settings.load().max_failed_attempts
            else None
        )
        self._users.update_after_failed_login(user["id"], new_count, locked_until)
