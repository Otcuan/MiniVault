from fastapi import APIRouter, Depends, Request, status

from src.api.schemas import VaultInitRequest, VaultStatusResponse, VaultUnlockRequest
from src.core.vault import VaultService


router = APIRouter(prefix="/v1/vault", tags=["Vault Core"])


def get_vault_service(request: Request) -> VaultService:
    return request.app.state.vault_service


@router.get("/status", response_model=VaultStatusResponse)
def get_status(service: VaultService = Depends(get_vault_service)) -> dict:
    return service.status()


@router.post("/init", response_model=VaultStatusResponse, status_code=status.HTTP_201_CREATED)
def initialize(
    payload: VaultInitRequest,
    service: VaultService = Depends(get_vault_service),
) -> dict:
    return service.initialize(payload.master_passphrase)


@router.post("/unlock", response_model=VaultStatusResponse)
def unlock(
    payload: VaultUnlockRequest,
    service: VaultService = Depends(get_vault_service),
) -> dict:
    return service.unlock(payload.master_passphrase)


@router.post("/lock", response_model=VaultStatusResponse)
def lock(service: VaultService = Depends(get_vault_service)) -> dict:
    return service.lock()
