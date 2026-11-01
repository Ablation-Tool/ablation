# GUIAI platform packages

These packages contain the GUIAI wheel and its Python dependencies for offline Python installation. System prerequisites can still require network access and approval.

## macOS

Use `GUIAI-macOS.zip`. Extract it and run `bash install_macos.sh` with Python 3.10 or newer that includes Tkinter. The installer creates `.venv` inside the extracted directory and installs without an index or separate METRIX checkout.

macOS uses the **Tk fallback interface**, not GTK/VTE. It has not been validated on macOS on this build host.

## Windows

Use `GUIAI-Windows-WSL.zip`. Review `Install-GUIAI.ps1`, then run it with PowerShell. The installer uses Ubuntu through WSL, installs the native GTK/VTE dependencies with `sudo`, clones Ablation into the Ubuntu home directory if needed, and installs the bundled wheel.

Windows requires **WSL with WSLg or another X server**. It is not a native Windows GUI package and may require a restart and Ubuntu first-run setup. It has not been validated on Windows on this build host.

The current terminal implementation is POSIX-specific. A native Windows ConPTY port would be separate work.
