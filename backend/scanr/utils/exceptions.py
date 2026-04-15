class ScanRError(Exception):
    """Base exception for ScanR."""


class ScanNotFoundError(ScanRError):
    pass


class ScanAlreadyRunningError(ScanRError):
    pass


class PluginError(ScanRError):
    pass


class VaultError(ScanRError):
    pass


class InvalidTargetError(ScanRError):
    pass
