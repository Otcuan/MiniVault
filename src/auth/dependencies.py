from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.auth.exceptions import UnauthenticatedError
from src.auth.session import hash_token, is_expired
from src.auth.session_repository import SessionRepository


bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: int
    email: str
    token: str


def get_session_repository(request: Request) -> SessionRepository:
    return request.app.state.session_repository


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise UnauthenticatedError()
    token = credentials.credentials.strip()
    if not token:
        raise UnauthenticatedError()

    session = get_session_repository(request).find_active_by_token_hash(hash_token(token))
    if session is None:
        raise UnauthenticatedError()
    expires_at = datetime.fromisoformat(session["expires_at"])
    if is_expired(expires_at):
        raise UnauthenticatedError()
    return AuthenticatedUser(
        user_id=session["user_id"],
        email=session["user_email"],
        token=token,
    )
