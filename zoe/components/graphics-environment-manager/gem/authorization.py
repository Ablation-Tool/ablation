from __future__ import annotations

import getpass
import os
import subprocess


OWNER_DISPLAY_NAME = "Nicholas Michael Kloster"


def explicit_command(arguments, *, approved=False, principal=None):
    if approved is not True:
        raise PermissionError("an explicit owner-approved action is required")
    if os.geteuid() == 0:
        raise PermissionError("Zoe does not execute owner commands as root")
    expected = principal or getpass.getuser()
    if getpass.getuser() != expected:
        raise PermissionError("the current OS session is not the approved principal")
    if not isinstance(arguments, (list, tuple)) or not arguments:
        raise ValueError("command must be a nonempty argument list")
    if any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in arguments):
        raise ValueError("command arguments must be nonempty strings without NUL bytes")
    return list(arguments)


def launch_explicit(arguments, *, approved=False, principal=None, **options):
    command = explicit_command(arguments, approved=approved, principal=principal)
    options.setdefault("shell", False)
    if options["shell"] is not False:
        raise ValueError("shell execution is not permitted")
    return subprocess.Popen(command, **options)
