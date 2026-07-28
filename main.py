from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.api.audit_routes import router as audit_router
from src.api.auth_routes import router as auth_router
from src.api.core_routes import router as core_router
from src.api.kv_routes import router as kv_router
from src.api.transit_routes import router as transit_router
from src.audit.repository import AuditRepository
from src.auth.exceptions import (
    AccountLockedError,
    DuplicateEmailError,
    InvalidCredentialsError,
    PassphraseMismatchError,
    UnauthenticatedError,
    WeakPassphraseError,
)
from src.auth.repository import UserRepository
from src.auth.service import AuthService
from src.auth.session_repository import SessionRepository
from src.core.exceptions import (
    InvalidMasterPassphraseError,
    InvalidMasterPassphrasePolicyError,
    StorageError,
    VaultAlreadyInitializedError,
    VaultConfigCorruptedError,
    VaultLockedError,
    VaultNotInitializedError,
)
from src.core import settings
from src.core.state import VaultState
from src.core.vault import VaultService
from src.kv.exceptions import (
    InvalidVersionError,
    PermissionDeniedError,
    RecordNotFoundError,
    RecordTamperedError,
)
from src.kv.repository import KvRepository
from src.kv.service import KvService
from src.storage.config_store import JsonConfigStore
from src.storage.database import Database
from src.transit.exceptions import (
    InvalidBase64PayloadError,
    InvalidDigestLengthError,
    InvalidKeyUsageError,
    InvalidKeyNameError,
    InvalidMessageTypeError,
    InvalidSigningAlgorithmError,
    KeyAlreadyExistsError,
    KeyUnavailableError,
    KeyVersionUnavailableError,
    MalformedCiphertextError,
    TransitTamperedError,
)
from src.transit.repository import NamedKeyRepository
from src.transit.service import TransitService


def create_app(
    config_path: Optional[Path] = None,
    database_path: Optional[Path] = None,
) -> FastAPI:
    """Build the application. Paths fall back to the environment settings."""
    configured = settings.load()
    vault_service = VaultService(
        JsonConfigStore(config_path or configured.config_path), VaultState()
    )
    database = Database(database_path or configured.database_path)
    users = UserRepository(database)
    sessions = SessionRepository(database)
    audit = AuditRepository(database)
    auth_service = AuthService(users, sessions)
    kv_service = KvService(vault_service, KvRepository(database), audit)
    transit_service = TransitService(vault_service, NamedKeyRepository(database), audit)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        # Section 0.1: a restart always comes back locked. The DEK lives only in
        # process memory, so a fresh process simply has nothing to unlock with.
        vault_service.lock()
        app.state.vault_service = vault_service
        app.state.database = database
        app.state.auth_service = auth_service
        app.state.session_repository = sessions
        app.state.audit_repository = audit
        app.state.kv_service = kv_service
        app.state.transit_service = transit_service
        yield
        vault_service.lock()

    app = FastAPI(
        title="Mini Vault",
        version="2.0.0",
        description="Secure KV storage and Transit cryptography service.",
        lifespan=lifespan,
    )
    app.include_router(core_router)
    app.include_router(auth_router)
    app.include_router(kv_router)
    app.include_router(transit_router)
    app.include_router(audit_router)
    register_error_handlers(app)

    @app.get("/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok"}

    return app


def register_error_handlers(app: FastAPI) -> None:
    """Map internal exceptions to stable {error, message} responses.

    Responses never carry a stack trace, a cryptographic cause, or anything that
    would let a caller distinguish "does not exist" from "not yours".
    """
    handlers = [
        (VaultAlreadyInitializedError, 409, "VAULT_ALREADY_INITIALIZED", "Vault has already been initialized"),
        (VaultNotInitializedError, 409, "VAULT_NOT_INITIALIZED", "Vault has not been initialized"),
        (InvalidMasterPassphrasePolicyError, 400, "WEAK_MASTER_PASSPHRASE", "Master Passphrase does not meet the minimum policy"),
        (InvalidMasterPassphraseError, 401, "UNLOCK_FAILED", "Unable to unlock Vault"),
        (VaultLockedError, 423, "VAULT_LOCKED", "Vault is locked"),
        (VaultConfigCorruptedError, 500, "VAULT_CONFIG_INVALID", "Vault configuration is invalid"),
        (StorageError, 500, "STORAGE_ERROR", "A storage operation failed"),
        (DuplicateEmailError, 409, "EMAIL_ALREADY_REGISTERED", "Email already registered"),
        (PassphraseMismatchError, 400, "PASSPHRASE_MISMATCH", "Passphrase confirmation does not match"),
        (WeakPassphraseError, 400, "WEAK_PASSPHRASE", "Passphrase does not meet the minimum policy"),
        (InvalidCredentialsError, 401, "INVALID_CREDENTIALS", "Invalid email or passphrase"),
        (AccountLockedError, 423, "ACCOUNT_LOCKED", "Account is temporarily locked"),
        (UnauthenticatedError, 401, "UNAUTHENTICATED", "Missing, invalid, or expired session token"),
        (PermissionDeniedError, 403, "PERMISSION_DENIED", "You do not have access to this resource"),
        (RecordNotFoundError, 404, "NOT_FOUND", "Record not found"),
        (RecordTamperedError, 409, "TAMPER_DETECTED", "Stored record failed integrity verification"),
        (InvalidVersionError, 400, "INVALID_VERSION", "Version must be a positive integer"),
        (KeyAlreadyExistsError, 409, "KEY_ALREADY_EXISTS", "A key with this name already exists"),
        (KeyUnavailableError, 403, "PERMISSION_DENIED", "The key is unavailable"),
        (KeyVersionUnavailableError, 404, "KEY_VERSION_NOT_FOUND", "The requested key version does not exist"),
        (InvalidKeyUsageError, 400, "INVALID_KEY_USAGE", "The key cannot be used for this operation"),
        (InvalidSigningAlgorithmError, 400, "INVALID_SIGNING_ALGORITHM", "The signing algorithm does not match the key"),
        (InvalidMessageTypeError, 400, "INVALID_MESSAGE_TYPE", "message_type must be RAW or DIGEST"),
        (InvalidDigestLengthError, 400, "INVALID_DIGEST_LENGTH", "SHA-256 digest must contain exactly 32 bytes"),
        (InvalidBase64PayloadError, 400, "INVALID_BASE64", "Payload must be valid Base64"),
        (InvalidKeyNameError, 400, "INVALID_KEY_NAME", "Key name must contain only letters, digits, dot, underscore, or hyphen"),
        (MalformedCiphertextError, 400, "MALFORMED_CIPHERTEXT", "Ciphertext format is invalid"),
        (TransitTamperedError, 409, "TAMPER_DETECTED", "Ciphertext or encrypted key material failed integrity verification"),
    ]

    for exception_type, status_code, error, message in handlers:
        async def handler(
            request: Request,
            exception: Exception,
            _status=status_code,
            _error=error,
            _message=message,
        ) -> JSONResponse:
            return JSONResponse(
                status_code=_status,
                content={"error": _error, "message": _message},
            )

        app.add_exception_handler(exception_type, handler)


app = create_app()
