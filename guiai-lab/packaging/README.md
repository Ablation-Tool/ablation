# GUIAI platform packages

These packages contain the GUIAI wheel and its Python dependencies for offline Python installation. Python, Tkinter, and optional Linux GTK/VTE system prerequisites are separate. METRIX is bundled; no separate checkout, AI model, or API credentials are installed.

## Universal installer

**[Start with the all-platform installation guide](../INSTALL.md).** It includes the copy-paste AI Agent prompt, manual platform instructions, and the separate CLI-only section.

Download and review `forall.py` from the [latest release](https://github.com/Ablation-Tool/ablation/releases/latest), then run `python forall.py`. Alternatively, paste the [universal install prompt](../INSTALL-PROMPT.md) into your AI Agent and type `/forall`.

The installer selects the native package for the current operating system, downloads the release checksum file and package over HTTPS, verifies SHA256 before extraction, rejects unsafe archive paths, runs the platform installer, and performs native validation. It creates a new installation under the current user's data directory and does not require `sudo`. An existing destination is never overwritten; choose a new empty directory with `--directory`.

This installs GUIAI and its required Python dependencies, not the optional full Ablation analysis environment or an AI Agent. A network connection is needed for the initial download. Subsequent Python package installation uses only the bundled wheels. `/forall` is an instruction interpreted through the install prompt, not a built-in command available in every CLI.

## Linux

Use `GUIAI-Linux.zip` with Python 3.10 or newer and Tkinter. Extract it and run `bash install_linux.sh`. The installer creates `.venv` inside the extracted directory, installs the Python dependencies offline, and runs the native stress suite unless `SKIP_TESTS=1` is set.

Linux can use the native GTK/VTE interface when the distribution's GTK, VTE, and Python GObject packages are installed. The installer uses `--system-site-packages` so those system libraries remain visible. Otherwise, use `--toolkit tk` for the single-investigation Tk interface. See the [workbench guide](../README.md) for Ubuntu/Debian prerequisites.

## macOS

Use `GUIAI-macOS.zip` with Python 3.10 or newer that includes Tkinter. Extract it and run `bash install_macos.sh`. The installer creates `.venv` inside the extracted directory, installs without an index or separate METRIX checkout, and creates `Ablation.app` beside it.

Open **Ablation.app** to choose a binary or material directory, project directory, and optional installed AI Agent. The setup window opens the existing GUIAI workbench; it does not install a model or credentials. The app includes its Python environment and `Ablation.icns` icon and can be moved to another folder on the same Mac. For scripted use, `Contents/MacOS/Ablation` forwards arguments to `guiai`, including `desktop`, `--agent`, and `--agent-command`.

macOS uses the **native Tk interface with POSIX PTY**, not GTK/VTE. The app is built locally and is not signed or Apple-notarized. The installer validates shell wrapping, interactive PTY, cleanup, branding/layout/project saving, first-run setup, bundle execution, relocation, and Launch Services opening unless `SKIP_TESTS=1` is set. A dedicated `macos-latest` CI workflow builds and validates the package.

## Native Windows

Use `GUIAI-Windows-Native.zip` with Python 3.11 x64 and Tcl/Tk support. Extract it and run `Install-WindowsNative.ps1` with PowerShell. The installer creates `.venv` in the extracted directory and installs offline using the bundled wheels.

This package uses the **native Tk interface with ConPTY**, not WSL. The installer runs native session-wrapper, interactive-terminal, and process-cleanup tests unless `-SkipTests` is supplied. A dedicated `windows-latest` CI workflow builds and validates the package.

## Windows WSL alternative

Use `GUIAI-Windows-WSL.zip`. Review `Install-GUIAI.ps1`, then run it with PowerShell. This alternative installs Ubuntu through WSL and the native Linux GTK/VTE dependencies with `sudo`.

Windows WSL requires **WSL with WSLg or another X server** and may require a restart and Ubuntu first-run setup. It is not a native Windows GUI package. The native Windows terminal uses ConPTY; the GTK/VTE interface remains Linux-specific.
