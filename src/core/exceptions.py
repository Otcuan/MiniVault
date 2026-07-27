class VaultError(Exception):
    """Base class for Vault errors."""


class VaultAlreadyInitializedError(VaultError):
    pass


class VaultNotInitializedError(VaultError):
    pass


class VaultLockedError(VaultError):
    pass


class InvalidMasterPassphraseError(VaultError):
    pass


class InvalidMasterPassphrasePolicyError(VaultError):
    pass


class VaultConfigCorruptedError(VaultError):
    pass


class StorageError(VaultError):
    pass
