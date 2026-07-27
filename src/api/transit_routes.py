from fastapi import APIRouter, Depends, Request, status

from src.api.transit_schemas import (
    CreateKeyRequest,
    CreateSigningKeyRequest,
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    KeyListResponse,
    KeyMetadata,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)
from src.auth.dependencies import AuthenticatedUser, get_current_user
from src.transit.service import TransitService


router = APIRouter(prefix="/v1/transit", tags=["Transit Engine"])


def get_transit_service(request: Request) -> TransitService:
    return request.app.state.transit_service


@router.post("/keys", response_model=KeyMetadata, status_code=status.HTTP_201_CREATED)
def create_key(
    payload: CreateKeyRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return service.create_key(current_user.email, payload.key_name)


@router.post(
    "/signing-keys",
    response_model=KeyMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_signing_key(
    payload: CreateSigningKeyRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return service.create_signing_key(
        current_user.email,
        payload.key_name,
        payload.signing_algorithm,
    )


@router.get("/keys", response_model=KeyListResponse)
def list_keys(
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return {"keys": service.list_keys(current_user.email)}


@router.post("/keys/{key_name}/revoke", response_model=KeyMetadata)
def revoke_key(
    key_name: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return service.revoke_key(current_user.email, key_name)


@router.post("/encrypt", response_model=EncryptResponse)
def encrypt(
    payload: EncryptRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return service.encrypt(current_user.email, payload.key_name, payload.plaintext_b64)


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(
    payload: DecryptRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return service.decrypt(current_user.email, payload.ciphertext)


@router.post("/sign", response_model=SignResponse)
def sign(
    payload: SignRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return service.sign(
        current_user.email,
        payload.key_name,
        payload.message_b64,
        payload.message_type,
        payload.signing_algorithm,
    )


@router.post("/verify", response_model=VerifyResponse)
def verify(
    payload: VerifyRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: TransitService = Depends(get_transit_service),
) -> dict:
    return service.verify(
        current_user.email,
        payload.key_name,
        payload.message_b64,
        payload.message_type,
        payload.signature_b64,
        payload.signing_algorithm,
    )
