class KvError(Exception):
    pass


class RecordNotFoundError(KvError):
    pass


class RecordTamperedError(KvError):
    pass


class PermissionDeniedError(KvError):
    pass
