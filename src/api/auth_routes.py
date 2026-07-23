from fastapi import APIRouter, Depends, Request, status

from src.api.auth_schemas import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse
from src.auth.service import AuthService

router = APIRouter(prefix="/v1/auth", tags=["Authentication"])


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    payload: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    return service.register(
        email=payload.email,
        passphrase=payload.passphrase,
        confirm_passphrase=payload.confirm_passphrase,
    )


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def login_user(
    payload: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    return service.login(email=payload.email, passphrase=payload.passphrase)