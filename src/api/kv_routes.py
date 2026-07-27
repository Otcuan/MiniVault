from fastapi import APIRouter, Depends, Query, Request, Response, status

from src.api.kv_schemas import KvReadResponse, KvWriteRequest, KvWriteResponse
from src.auth.dependencies import AuthenticatedUser, get_current_user
from src.kv.service import KvService


router = APIRouter(prefix="/v1/kv", tags=["KV Engine"])


def get_kv_service(request: Request) -> KvService:
    return request.app.state.kv_service


@router.post("/entries", response_model=KvWriteResponse)
def write_entry(
    payload: KvWriteRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> dict:
    return service.write(current_user.email, payload.path, payload.data)


@router.get("/entries", response_model=KvReadResponse)
def read_entry(
    path: str = Query(..., min_length=1, max_length=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> dict:
    return {"data": service.read(current_user.email, path)}


@router.delete("/entries", status_code=status.HTTP_204_NO_CONTENT)
def delete_entry(
    path: str = Query(..., min_length=1, max_length=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: KvService = Depends(get_kv_service),
) -> Response:
    service.delete(current_user.email, path)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
