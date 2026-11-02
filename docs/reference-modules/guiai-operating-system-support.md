# Operating System Support

## Purpose

GUIAI provides native workbenches for **Windows, MacOS, and Linux** while preserving the same authoritative session model: real agent terminals, independent investigation history, visual navigation, review controls, and saved preferences.

The interface adapts to the operating system rather than requiring a browser or a separate chatbot service.

## Linux

Linux uses the native **GTK/VTE** interface when its system packages are available, with a single-investigation Tk fallback.

- Python 3.10 or newer with Tkinter.
- GTK, VTE, Python GObject, and Cairo system packages for the full interface.
- X11 or XWayland for the native display.
- Multi-Lab tabs, native directory chooser, VTE terminals, native charts, and collapsible preferences.

Ubuntu/Debian prerequisites include `python3-venv`, `python3-tk`, `python3-gi`, `python3-cairo`, `python3-gi-cairo`, `gir1.2-gtk-3.0`, and `gir1.2-vte-2.91`. The Linux offline installer uses `--system-site-packages` so those native libraries remain visible.

## Windows

Native Windows uses **Tk with ConPTY**, not WSL.

- Python 3.11 x64 with Tcl/Tk support.
- Offline GUIAI wheel and bundled `pywinpty`, `pyte`, and `wcwidth` wheels.
- Native interactive terminal, process cleanup, layout selection, project saving, and Explorer evidence reveal.
- Native validation for the command wrapper, interactive ConPTY, output draining, and forced cleanup.

`GUIAI-Windows-Native.zip` contains the native installer. `GUIAI-Windows-WSL.zip` is a separate alternative for users who explicitly want Ubuntu through WSL with GTK/VTE; it is not required for the native Windows workbench.

## MacOS

MacOS uses **Tk with POSIX PTY** and a double-clickable `Ablation.app`.

- Python 3.10 or newer with Tkinter.
- Offline Python environment and native `Ablation.icns` branding.
- First-run selection for the RE target, project directory, and optional installed AI Agent.
- Native app execution through Launch Services and relocation-safe launchers on the same Mac.
- Finder evidence reveal and saved layout/project preferences.

The app is created locally and is not signed or Apple-notarized. It uses the Python installation used by the installer. `Contents/MacOS/Ablation` forwards normal GUIAI command-line arguments, and `--self-test` checks the bundled runtime.

## Installation and dependency model

The Universal OS Installation Prompt detects the operating system, downloads the appropriate native package, and verifies its SHA256 checksum. The default GUIAI choice installs the standard Ablation CLI and GUIAI into one environment; CLI Only is the explicit alternative for users who do not want the workbench.

GUIAI's own wheels are installed offline. Standard Ablation dependencies are downloaded from PyPI. Optional analysis extras, AI models, agent credentials, and model-provider configuration are not installed automatically.

## Implementation map

- `guiai-lab/packaging/build_linux.py`: Linux offline package
- `guiai-lab/packaging/build_windows_native.py`: native Windows package
- `guiai-lab/packaging/build_macos.py`: macOS offline package
- `guiai-lab/packaging/create_macos_app.py`: atomic `Ablation.app` creation, icon generation, and relocation-safe launchers
- `guiai-lab/packaging/forall.py`: OS detection, verified downloads, shared environment, and CLI verification
- `guiai-lab/guiai/gtk_app.py`: native Linux GTK/VTE workbench
- `guiai-lab/guiai/app.py` and `guiai-lab/metrix/desktop.py`: Tk workbench and terminal behavior

## Validation and boundaries

Native Windows and macOS CI tests cover wrapper execution, interactive terminals, process cleanup, branding, layouts, project saving, app execution, and relocation. Linux validation covers the full GTK suite, native Tk suite, desktop-input workflow, and offline installation.

These tests do not prove that every AI Agent's terminal interface or every display server behaves identically. GTK's independent Lab tabs are available only in the GTK interface; Windows and macOS use the single-investigation Tk interface. Agent-specific authentication and terminal behavior still require their own validation.
