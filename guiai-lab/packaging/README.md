# GUIAI platform packages

These packages contain the GUIAI wheel and its Python dependencies for offline Python installation. System prerequisites can still require network access and approval.

## macOS

Use `GUIAI-macOS.zip`. Extract it and run `bash install_macos.sh` with Python 3.10 or newer that includes Tkinter. The installer creates `.venv` inside the extracted directory and installs without an index or separate METRIX checkout.

macOS uses the **native Tk interface with POSIX PTY**, not GTK/VTE. The installer runs native shell-wrapper, interactive-terminal, and process-cleanup tests unless `SKIP_TESTS=1` is set. A dedicated `macos-latest` CI workflow builds and validates the package.

## Native Windows

Use `GUIAI-Windows-Native.zip` with Python 3.11 x64 and Tcl/Tk support. Extract it and run `Install-WindowsNative.ps1` with PowerShell. The installer creates `.venv` in the extracted directory and installs offline using the bundled wheels.

This package uses the **native Tk interface with ConPTY**, not WSL. The installer runs native session-wrapper, interactive-terminal, and process-cleanup tests unless `-SkipTests` is supplied. A dedicated `windows-latest` CI workflow builds and validates the package.

## Windows WSL alternative

Use `GUIAI-Windows-WSL.zip`. Review `Install-GUIAI.ps1`, then run it with PowerShell. This alternative installs Ubuntu through WSL and the native Linux GTK/VTE dependencies with `sudo`.

Windows WSL requires **WSL with WSLg or another X server** and may require a restart and Ubuntu first-run setup. It is not a native Windows GUI package. The native Windows terminal uses ConPTY; the GTK/VTE interface remains Linux-specific.
