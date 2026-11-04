# Operating System Support

## Purpose

GEM provides native workbenches for **Windows, MacOS, and Linux** while preserving the same authoritative session model: real agent terminals, independent investigation history, visual navigation, review controls, and saved preferences.

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
- Offline GEM wheel and bundled `pywinpty`, `pyte`, and `wcwidth` wheels.
- Native interactive terminal, process cleanup, layout selection, project saving, and Explorer evidence reveal.
- Native validation for the command wrapper, interactive ConPTY, output draining, and forced cleanup.

`GEM-Windows-Native.zip` contains the native installer. `GEM-Windows-WSL.zip` is a separate alternative for users who explicitly want Ubuntu through WSL with GTK/VTE; it is not required for the native Windows workbench.

## MacOS

MacOS uses **Tk with POSIX PTY** and a double-clickable `GEM.app`.

- Python 3.10 or newer with Tkinter.
- Offline Python environment and native `Ablation.icns` branding.
- Direct GEM home screen with **Open binary** and **Open directory** actions, stable per-target sessions, and installed AI Agent detection.
- Native app execution through Launch Services and relocation-safe launchers on the same Mac.
- Finder evidence reveal and saved layout/project preferences.

The app is created locally and is not signed or Apple-notarized. It uses the Python installation used by the installer. `Contents/MacOS/GEM` forwards normal GEM command-line arguments, and `--self-test` checks the bundled runtime.

## Installation and dependency model

The Universal OS Installation Prompt detects the operating system, downloads the appropriate native package, and verifies its SHA256 checksum. The default GEM choice installs the standard Ablation CLI and GEM into one environment; CLI Only is the explicit alternative for users who do not want the workbench.

GEM's own wheels are installed offline. Standard Ablation dependencies are downloaded from PyPI. Optional analysis extras, AI models, agent credentials, and model-provider configuration are not installed automatically.

## Implementation map

- `gem-lab/packaging/build_linux.py`: Linux offline package
- `gem-lab/packaging/build_windows_native.py`: native Windows package
- `gem-lab/packaging/build_macos.py`: macOS offline package
- `gem-lab/packaging/create_macos_app.py`: atomic `GEM.app` creation, icon generation, and relocation-safe launchers
- `gem-lab/packaging/forall.py`: OS detection, verified downloads, shared environment, and CLI verification
- `gem-lab/gem/gtk_app.py`: native Linux GTK/VTE workbench
- `gem-lab/gem/app.py` and `gem-lab/metrix/desktop.py`: Tk workbench and terminal behavior

## Validation and boundaries

Native Windows and macOS CI tests cover wrapper execution, interactive terminals, process cleanup, branding, layouts, project saving, app execution, and relocation. Linux validation covers the full GTK suite, native Tk suite, desktop-input workflow, and offline installation.

These tests do not prove that every AI Agent's terminal interface or every display server behaves identically. GTK's independent Lab tabs are available only in the GTK interface; Windows and macOS use the single-investigation Tk interface. Agent-specific authentication and terminal behavior still require their own validation.
