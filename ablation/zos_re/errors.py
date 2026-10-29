class ZosReError(Exception):
    pass


class FormatError(ZosReError):
    pass


class UnsupportedFormatError(ZosReError):
    pass


class SafetyError(ZosReError):
    pass
