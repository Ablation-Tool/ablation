# Install Ablation

## GUIAI

<details>
<summary><strong>Installation Prompt</strong></summary>

Copy this entire prompt into the AI Agent you want to use. It installs GUIAI and its dependencies directly; `/forall` can be used afterward as a short name for the same request.

```text
Install GUIAI for Ablation and launch it with you—the AI Agent I am currently using—embedded in its terminal.

Check my operating system and Python first. Native Windows requires Python 3.11 x64 with Tcl/Tk; macOS and Linux require Python 3.10 or newer with Tkinter. If a prerequisite is missing, explain what is needed and ask before making system changes.

Download and review this installer:
https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py

Run it with the checked Python. It selects the correct native package, verifies SHA256, installs GUIAI and its required Python dependencies offline, and runs native validation. Do not pipe a downloaded script into an interpreter, use sudo, overwrite an existing installation, skip failed tests, or bypass my permissions.

Ask me for the RE target and project/session directory if needed. Keep the project outside the target. On macOS, open the generated Ablation.app. On Windows and macOS, use --toolkit tk when launching through the CLI. Use your actual executable for the embedded AI Agent; if you cannot identify it, ask me instead of substituting another agent.

Do not install an AI model, credentials, optional analysis extras, or firmware analysis. Do not execute the RE target.

Report the operating system, installed version, installation and project paths, validation result, and exact launch command. Confirm that the native window opens and your real CLI starts inside it.
```

</details>

<details>
<summary><strong>Linux</strong></summary>

On Ubuntu or Debian:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-tk python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91
curl -fLO https://github.com/Ablation-Tool/ablation/releases/latest/download/GUIAI-Linux.zip
mkdir Ablation-Linux
unzip -q GUIAI-Linux.zip -d Ablation-Linux
cd Ablation-Linux
bash install_linux.sh
```

Launch with your installed AI Agent:

```bash
. .venv/bin/activate
guiai desktop /path/to/target --session /path/to/project --agent kimi
```

Linux uses GTK/VTE when available, with Tk as a fallback. The GUI requires X11 or XWayland. Replace `kimi` with `claude`, `codex`, or another installed agent executable.

</details>

<details>
<summary><strong>MacOS</strong></summary>

Use Python 3.10 or newer with Tkinter. In Terminal:

```bash
curl -fLO https://github.com/Ablation-Tool/ablation/releases/latest/download/GUIAI-macOS.zip
mkdir Ablation-macOS
unzip -q GUIAI-macOS.zip -d Ablation-macOS
cd Ablation-macOS
bash install_macos.sh
open Ablation.app
```

In the first-run window, choose the **RE target**, a **project directory outside the target**, and optionally your installed AI Agent. Select an existing project to continue saved work.

The installer creates `Ablation.app` and runs native validation. You can move the app on the same Mac; it uses the Python installation used by the installer. It is not signed or Apple-notarized.

Verify the app with:

```bash
Contents/MacOS/Ablation --self-test
```

The result should be `GUIAI_MACOS_APP_OK`.

</details>

<details>
<summary><strong>Windows</strong></summary>

Use **Python 3.11 x64** with Tcl/Tk support. In PowerShell:

```powershell
Invoke-WebRequest -Uri "https://github.com/Ablation-Tool/ablation/releases/latest/download/GUIAI-Windows-Native.zip" -OutFile "GUIAI-Windows-Native.zip"
Expand-Archive -Path "GUIAI-Windows-Native.zip" -DestinationPath "Ablation-Windows"
Set-Location "Ablation-Windows"
```

Review `Install-WindowsNative.ps1`. If you approve it, allow and run the reviewed local script:

```powershell
Unblock-File -Path ".\Install-WindowsNative.ps1"
& ".\Install-WindowsNative.ps1"
```

Launch with your installed AI Agent:

```powershell
.\.venv\Scripts\guiai.exe desktop "C:\path\to\target" --session "C:\path\to\project" --toolkit tk --agent kimi
```

Replace `kimi` with `claude`, `codex`, or another installed executable. Native Windows uses Tk with ConPTY; WSL is not required.

</details>

## CLI only

These instructions install the **Ablation command-line tools without the GUIAI workbench**. Use Python 3.10 or newer and a project-local virtual environment.

Create and activate the environment on Linux or macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
```

Or on Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the standard package and verify it:

```bash
python -m pip install ablation-tool
ablation --help
```

To install from a source checkout instead, run `python -m pip install .` from the repository root. Optional analysis extras, models, provider configuration, and credentials remain separate. No RE target is executed during installation.

For project saving, custom agent arguments, and the native workbench, see the [GUIAI guide](README.md) and [platform package details](packaging/README.md).
