PATH_PREFIX = "secret/"


def extract_owner_email_from_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith(PATH_PREFIX):
        raise ValueError("Invalid KV path")
    remainder = path[len(PATH_PREFIX) :]
    segments = remainder.split("/", 1)
    if len(segments) != 2 or not segments[0] or not segments[1]:
        raise ValueError("Invalid KV path")
    return segments[0].strip().lower()
