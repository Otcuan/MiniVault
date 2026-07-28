class KvError(Exception):
    pass


class RecordNotFoundError(KvError):
    pass


class RecordTamperedError(KvError):
    pass


class PermissionDeniedError(KvError):
    pass


class InvalidVersionError(KvError):
    """Requested KV version is not a positive integer."""
