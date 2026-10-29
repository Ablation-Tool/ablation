class IbmZosError(Exception):
    pass


class FormatError(IbmZosError):
    pass


class UnsupportedFormatError(IbmZosError):
    pass


class SafetyError(IbmZosError):
    pass
