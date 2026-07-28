class TransitError(Exception):
    pass


class MalformedCiphertextError(TransitError):
    pass


class TransitTamperedError(TransitError):
    pass


class KeyAlreadyExistsError(TransitError):
    pass


class KeyUnavailableError(TransitError):
    """Generic response for nonexistent, deleted or foreign keys."""


class KeyVersionUnavailableError(TransitError):
    """Ciphertext references a key version that does not exist."""


class InvalidKeyUsageError(TransitError):
    pass


class InvalidSigningAlgorithmError(TransitError):
    pass


class InvalidMessageTypeError(TransitError):
    pass


class InvalidDigestLengthError(TransitError):
    pass


class InvalidBase64PayloadError(TransitError):
    pass


class InvalidKeyNameError(TransitError):
    pass
