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

MIN_PASSPHRASE_LENGTH = 12
MAX_FAILED_ATTEMPTS = 5

# Hash "giả" tính sẵn 1 lần khi module load, dùng khi email không tồn tại,
# để verify_password() vẫn tốn thời gian tương đương như khi email có thật
# -> tránh lộ qua độ trễ phản hồi việc "email này có đăng ký hay không".
_DUMMY_PASSWORD_HASH = hash_password("timing-attack-mitigation-placeholder")


class AuthService:
    def __init__(self, user_repository: UserRepository, session_repository: SessionRepository) -> None:
        self._users = user_repository
        self._sessions = session_repository

    def register(self, email: str, passphrase: str, confirm_passphrase: str) -> dict:
        if passphrase != confirm_passphrase:
            raise PassphraseMismatchError()
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise WeakPassphraseError()

        password_hash = hash_password(passphrase)
        user_row = self._users.create(email, password_hash)

        return {"email": user_row["email"], "created_at": user_row["created_at"]}

    def login(self, email: str, passphrase: str) -> dict:
        user = self._users.get_by_email(email)

        if user is None:
            verify_password(passphrase, _DUMMY_PASSWORD_HASH)  # giữ thời gian phản hồi đều
            raise InvalidCredentialsError()

        if user["locked_until"] is not None:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now(timezone.utc) < locked_until:
                raise AccountLockedError()

        if not verify_password(passphrase, user["password_hash"]):
            self._register_failed_attempt(user)
            raise InvalidCredentialsError()

        self._users.reset_login_failures(user["id"])

        token = generate_session_token()
        expires_at = compute_expiry()
        self._sessions.create(user["id"], hash_token(token), expires_at.isoformat())

        return {"token": token, "expires_at": expires_at.isoformat()}

    def _register_failed_attempt(self, user) -> None:
        new_count = user["failed_attempts"] + 1
        locked_until = compute_lockout_until().isoformat() if new_count >= MAX_FAILED_ATTEMPTS else None
        self._users.update_after_failed_login(user["id"], new_count, locked_until)