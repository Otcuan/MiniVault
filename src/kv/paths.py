PATH_PREFIX = "secret/"


def extract_owner_email_from_path(path: str) -> str:
    """Tách phần email ra khỏi path dạng 'secret/<email>/...'.
    Raise ValueError nếu path không đúng định dạng tối thiểu."""
    if not path.startswith(PATH_PREFIX):
        raise ValueError("Path must start with 'secret/'")

    remainder = path[len(PATH_PREFIX):]
    segments = remainder.split("/", 1)

    if len(segments) < 2 or not segments[0] or not segments[1]:
        raise ValueError("Path must follow 'secret/<email>/<name>' format")

    return segments[0]