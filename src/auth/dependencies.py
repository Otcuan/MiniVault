from datetime import datetime
from typing import Optional

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.auth.exceptions import UnauthenticatedError
from src.auth.session import hash_token, is_expired
from src.auth.session_repository import SessionRepository

bearer_scheme = HTTPBearer(auto_error=False)  # auto_error=False -> tự raise lỗi của mình, không để FastAPI raise 403 mặc định


class AuthenticatedUser:
    def __init__(self, user_id: int, email: str) -> None:
        self.user_id = user_id
        self.email = email


def get_session_repository(request: Request) -> SessionRepository:
    return request.app.state.session_repository


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> AuthenticatedUser:
    if credentials is None or not credentials.credentials:
        raise UnauthenticatedError()

    token = credentials.credentials.strip()
    if not token:
        raise UnauthenticatedError()

    session_repository = get_session_repository(request)
    session = session_repository.find_active_by_token_hash(hash_token(token))

    if session is None:
        raise UnauthenticatedError()

    expires_at = datetime.fromisoformat(session["expires_at"])
    if is_expired(expires_at):
        raise UnauthenticatedError()

    return AuthenticatedUser(user_id=session["user_id"], email=session["user_email"])