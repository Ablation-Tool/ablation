class TimiError(Exception):
    pass


class FormatError(TimiError):
    pass


class UnsupportedFormatError(TimiError):
    pass


class SafetyError(TimiError):
    pass
