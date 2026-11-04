# GEM platform packages

These packages contain the GEM wheel and its Python dependencies for offline Python installation. Python, Tkinter, and optional Linux GTK/VTE system prerequisites are separate. METRIX and the pinned `tkinterdnd2` native drag-and-drop bridge are bundled; no separate checkout, AI model, or API credentials are installed.

## Universal installer

**[Start with the Universal OS Installation Prompt](../INSTALL.md).** It asks you to choose **GEM** or **CLI Only**, then installs the appropriate tools for your operating system.

Download and review `forall.py` from the [latest release](https://github.com/Ablation-Tool/ablation/releases/latest), then run `python forall.py`. Alternatively, paste the [Universal OS Installation Prompt](../INSTALL-PROMPT.md) into your AI Agent and answer its GEM-or-CLI-only question.

The installer selects the native package for the current operating system, downloads the release checksum file and package over HTTPS, verifies SHA256 before extraction, rejects unsafe archive paths, and moves the verified package to a previously nonexistent destination before creating its virtual environment. It runs platform validation and verifies `gem launch --help` from the final installation path. It does not require `sudo`; choose a new empty directory with `--directory` when the default exists.

A Desktop icon is installed by default and opens GEM directly with in-app **Open binary** and **Open directory** actions. After target selection, GEM creates a stable per-target session, detects an installed Kimi, Claude, or Codex agent, and connects its terminal to the selected Lab session; an explicitly supplied agent command takes precedence, and `gem launch --no-agent` disables detection. The agent opens in the `gem-lab` root with the GEM environment needed to interact with the Lab: the repository's `gem-lab` directory for source checkouts, or `~/gem-lab` for packaged installations. If no supported agent is installed, the Lab opens without an embedded CLI. Use `python forall.py --no-desktop-shortcut` to opt out of the shortcut. If native installation fails, the new partial destination is retained for diagnosis and reported as incomplete; it is never presented as successful or silently deleted.

By default, this installs the **standard Ablation CLI and GEM together** in one environment. The native GEM package and its Python wheels are checksum-verified and installed offline. The standard Ablation CLI wheel is checksum-verified from the same release, and its dependencies are downloaded from PyPI. Optional analysis extras, AI models, credentials, and an AI Agent are not installed. Use `--gui-only` to install only the workbench.

A network connection is needed for the initial downloads and the standard Ablation dependencies. `/forall` is an instruction interpreted through the install prompt, not a built-in command available in every CLI.

After installation, the turned-A logo exposes **a11y Optimization**, **OS Optimization**, and **Debug**. Each audit is read-only until the user explicitly allows a displayed, bounded remediation request through an active embedded AI agent. Denying permission never invokes the terminal. Accessibility includes persistent colorblind-safe and high-contrast palettes, descriptive labels, text alternatives, and keyboard navigation; manual assistive-technology validation remains necessary.

## Linux

Use `GEM-Linux.zip` with Python 3.10 or newer and Tkinter. Extract it and run `bash install_linux.sh`. The installer creates `.venv` inside the extracted directory, installs the Python dependencies offline, and runs the native stress suite unless `SKIP_TESTS=1` is set.

The installer registers `gem-woven-diamond.png` and `re.gem.workbench.desktop` in the user's XDG data directory, then creates `GEM.desktop` in the directory reported by `xdg-user-dir DESKTOP`. It preserves a customized existing shortcut and sets GNOME trusted-launcher metadata where supported. Set `NO_DESKTOP_SHORTCUT=1` to install only the application-menu entry. If Desktop shortcuts are disabled by the desktop configuration, the application-menu installation still succeeds and the limitation is reported.

Linux can use the native GTK/VTE interface when the distribution's GTK, VTE, and Python GObject packages are installed. The installer uses `--system-site-packages` so those system libraries remain visible. Otherwise, use `--toolkit tk` for the single-investigation Tk interface. See the [workbench guide](../README.md) for Ubuntu/Debian prerequisites.

## macOS

Use `GEM-macOS.zip` with Python 3.10 or newer that includes Tkinter. Extract it and run `bash install_macos.sh`. The installer creates `.venv` inside the extracted directory, installs without an index or separate METRIX checkout, and creates `GEM.app` beside it.

Open **GEM.app** and choose **Open binary** or **Open directory** in the GEM home screen. After target selection, the app creates a stable per-target session and opens the workbench with an installed agent when available. The app includes its Python environment and `GEM.icns` icon and can be moved to another folder on the same Mac. For scripted use, `Contents/MacOS/GEM` forwards arguments to `gem`, including `desktop`, `--agent`, and `--agent-command`. A Desktop alias is created by default; set `NO_DESKTOP_SHORTCUT=1` to omit it, and an existing non-symlink at `~/Desktop/GEM.app` is never replaced.

macOS uses the **native Tk interface with POSIX PTY**, not GTK/VTE. The app is built locally and is not signed or Apple-notarized. The installer does not bypass privacy permissions, quarantine, or Gatekeeper; public production releases require Developer ID signing and notarization. The installer validates shell wrapping, interactive PTY, drag-and-drop, icon rendering, cleanup, branding/layout/project saving, home-screen target selection, bundle execution, relocation, and Launch Services opening unless `SKIP_TESTS=1` is set. A dedicated `macos-latest` CI workflow builds and validates the package.

## Native Windows

Use `GEM-Windows-Native.zip` with Python 3.11 x64 and Tcl/Tk support. Extract it and run `Install-WindowsNative.ps1` with PowerShell. The installer creates `.venv` in the extracted directory and installs offline using the bundled wheels.

The installer creates and validates `GEM.lnk` on the Windows Desktop. It targets `pythonw.exe -m gem launch --toolkit tk` and uses the bundled ICO artwork, so no console window is required. Pass `-NoDesktopShortcut` to omit it; `NO_DESKTOP_SHORTCUT=1` is also honored.

This package uses the **native Tk interface with ConPTY**, not WSL. The installer runs native session-wrapper, interactive-terminal, drag-and-drop, icon, and process-cleanup tests unless `-SkipTests` is supplied. A dedicated `windows-latest` CI workflow builds and validates the package.

## Windows WSL alternative

Use `GEM-Windows-WSL.zip`. Review `Install-GEM.ps1`, then run it with PowerShell. This alternative installs Ubuntu through WSL and the native Linux GTK/VTE dependencies with `sudo`.

Windows WSL requires **WSL with WSLg or another X server** and may require a restart and Ubuntu first-run setup. It is not a native Windows GUI package. The native Windows terminal uses ConPTY; the GTK/VTE interface remains Linux-specific.
