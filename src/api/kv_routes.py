from fastapi import APIRouter, Depends, Query, Request, status

from src.api.kv_schemas import KvReadResponse, KvWriteRequest, KvWriteResponse
from src.auth.dependencies import AuthenticatedUser, get_current_user
from src.kv.service import KvService

router = APIRouter(prefix="/v1/kv", tags=["KV Engine"])


def get_kv_service(request: Request) -> KvService:
    return request.app.state.kv_service


@router.post("/entries", response_model=KvWriteResponse, status_code=status.HTTP_200_OK)
def write_entry(
    payload: KvWriteRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> dict:
    # owner_email LUÔN lấy từ token đã xác thực, KHÔNG BAO GIỜ lấy từ payload
    return service.write(owner_email=current_user.email, path=payload.path, data=payload.data)


@router.get("/entries", response_model=KvReadResponse, status_code=status.HTTP_200_OK)
def read_entry(
    path: str = Query(..., min_length=1, max_length=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> dict:
    data = service.read(owner_email=current_user.email, path=path)
    return {"data": data}


@router.delete("/entries", status_code=status.HTTP_204_NO_CONTENT)
def delete_entry(
    path: str = Query(..., min_length=1, max_length=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> None:
    service.delete(owner_email=current_user.email, path=path)