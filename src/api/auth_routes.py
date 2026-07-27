from fastapi import APIRouter, Depends, Request, Response, status

from src.api.auth_schemas import LoginRequest, LoginResponse, RegisterRequest, RegisterResponse
from src.auth.dependencies import AuthenticatedUser, get_current_user
from src.auth.service import AuthService


router = APIRouter(prefix="/v1/auth", tags=["Authentication"])


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    return service.register(payload.email, payload.passphrase, payload.confirm_passphrase)


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    return service.login(payload.email, payload.passphrase)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service),
) -> Response:
    service.logout(current_user.token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
