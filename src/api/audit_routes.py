from fastapi import APIRouter, Depends, Query, Request

from src.api.audit_schemas import AuditListResponse, AuditVerifyResponse
from src.audit.repository import AuditRepository
from src.auth.dependencies import AuthenticatedUser, get_current_user


router = APIRouter(prefix="/v1/audit", tags=["Audit Log"])


def get_audit_repository(request: Request) -> AuditRepository:
    return request.app.state.audit_repository


@router.get("/entries", response_model=AuditListResponse)
def list_entries(
    limit: int = Query(100, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    repository: AuditRepository = Depends(get_audit_repository),
) -> dict:
    """A caller's own audit trail.

    Scoped to the session email for the same reason KV is: one user must not be
    able to enumerate another user's paths or key names through the log.
    """
    rows = repository.list_for_requester(current_user.email, limit)
    return {"entries": [dict(row) for row in rows]}


@router.get("/verify", response_model=AuditVerifyResponse)
def verify_chain(
    current_user: AuthenticatedUser = Depends(get_current_user),
    repository: AuditRepository = Depends(get_audit_repository),
) -> dict:
    """Recompute the hash chain over the whole log.

    Integrity is a property of the log as a whole, so this covers every entry,
    not just the caller's. It reveals only whether the chain still verifies and
    where it first breaks -- no entry content is returned.
    """
    return repository.verify()
