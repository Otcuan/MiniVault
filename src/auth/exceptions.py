class AuthError(Exception):
    pass


class DuplicateEmailError(AuthError):
    pass


class PassphraseMismatchError(AuthError):
    pass


class WeakPassphraseError(AuthError):
    pass


class InvalidCredentialsError(AuthError):
    pass


class AccountLockedError(AuthError):
    pass


class UnauthenticatedError(AuthError):
    pass
