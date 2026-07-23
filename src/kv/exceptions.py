class KvError(Exception):
    """Lớp cha cho mọi lỗi liên quan đến KV Engine."""


class RecordNotFoundError(KvError):
    """Không tìm thấy record tại path được yêu cầu."""


class RecordTamperedError(KvError):
    """Dữ liệu trên đĩa đã bị sửa — GCM tag không khớp khi giải mã."""


class PermissionDeniedError(KvError):
    """Path không thuộc quyền sở hữu của người gọi."""


class InvalidPathError(KvError):
    """Path không đúng định dạng secret/<email>/..."""