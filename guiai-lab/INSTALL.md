# Install Ablation

## GUIAI and Ablation

<details>
<summary><strong>Installation Prompt</strong></summary>

Copy this entire prompt into the AI Agent you want to use. It installs the standard Ablation CLI and GUIAI with their dependencies directly; `/forall` can be used afterward as a short name for the same request.

```text
Install the standard Ablation CLI and GUIAI, then launch GUIAI with you—the AI Agent I am currently using—embedded in its terminal.

Check my operating system and Python first. Native Windows requires Python 3.11 x64 with Tcl/Tk; macOS and Linux require Python 3.10 or newer with Tkinter. If a prerequisite is missing, explain what is needed and ask before making system changes.

Download and review this installer:
https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py

Run it with the checked Python. It selects the correct native package, verifies SHA256, and installs the standard Ablation CLI and GUIAI with their required dependencies. GUIAI's wheels install offline; standard Ablation dependencies are downloaded from PyPI. It verifies both ablation --help and guiai --help.

Do not pipe a downloaded script into an interpreter, use sudo, overwrite an existing installation, skip failed tests, or bypass my permissions.

Ask me for the RE target and project/session directory if needed. Keep the project outside the target. On macOS, open the generated Ablation.app. On Windows and macOS, use --toolkit tk when launching through the CLI. Use your actual executable for the embedded AI Agent; if you cannot identify it, ask me instead of substituting another agent.

Do not install an AI model, credentials, optional analysis extras, or firmware analysis. Do not execute the RE target.

Report the operating system, Ablation and GUIAI versions, installation and project paths, validation result, and exact launch command. Confirm that the native window opens and your real CLI starts inside it.
```

</details>

<details>
<summary><strong>Linux Installation Prompt</strong></summary>

```text
Install the standard Ablation CLI and GUIAI on Linux, then launch GUIAI with you—the AI Agent I am currently using—embedded in its terminal.

Check for Python 3.10 or newer, Tkinter, a virtual-environment tool, and an X11 or XWayland display. On Ubuntu or Debian, ask before installing missing packages with sudo apt install python3-venv python3-tk python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91.

Download and review https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py and run it with the checked Python. Use the default full installation, which includes both Ablation and GUIAI, verifies release checksums, installs GUIAI's wheels offline, and downloads standard Ablation dependencies from PyPI.

Do not overwrite existing files, use sudo for the Python installation, skip failed validation, or execute the RE target. Ask before privileged changes.

Verify ablation --help and guiai --help in the installed environment. Ask me for the RE target and a project directory outside it, then launch with your actual agent executable using guiai desktop TARGET --session PROJECT --agent AGENT_EXECUTABLE. If I need custom agent arguments, use --agent-command instead.

Do not install a model, credentials, or optional analysis extras. Report both versions, installation and project paths, validation results, and the exact launch command. Confirm that the workbench opens and your real CLI starts inside it.
```

</details>

<details>
<summary><strong>MacOS Installation Prompt</strong></summary>

```text
Install the standard Ablation CLI and GUIAI on macOS, then open Ablation.app with you—the AI Agent I am currently using—embedded in its terminal.

Check for Python 3.10 or newer with Tkinter. If it is missing, explain how to install a Python distribution that includes Tkinter and ask before making system changes.

Download and review https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py and run it with the checked Python. Use the default full installation, which includes both Ablation and GUIAI, verifies release checksums, installs GUIAI's wheels offline, and downloads standard Ablation dependencies from PyPI.

Do not overwrite existing files, use sudo for the Python installation, skip failed validation, or execute the RE target. Do not bypass macOS security settings or my permissions.

Verify ablation --help and guiai --help, and run Contents/MacOS/Ablation --self-test from the installation directory. Open the generated Ablation.app. Ask me to choose the RE target, a project directory outside it, and your actual executable. The app is locally built and is not signed or Apple-notarized.

Do not install a model, credentials, or optional analysis extras. Report both versions, installation and project paths, validation results, and the exact app and CLI launch commands. Confirm that the app opens and your real CLI starts inside it.
```

</details>

<details>
<summary><strong>Windows Installation Prompt</strong></summary>

```text
Install the standard Ablation CLI and GUIAI on Windows, then launch GUIAI with you—the AI Agent I am currently using—embedded in its terminal.

Check for Python 3.11 x64 with Tcl/Tk support. If it is missing, explain how to install it and ask before making system changes. Do not require WSL.

Download and review https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py and run it with the checked Python. Use the default full installation, which includes both Ablation and GUIAI, verifies release checksums, installs GUIAI's wheels offline, and downloads standard Ablation dependencies from PyPI.

Do not overwrite existing files, use a global Python installation, skip failed validation, or execute the RE target. Preserve my permissions and existing configuration.

Verify ablation --help and guiai --help in the installed environment. Ask me for the RE target and a project directory outside it, then launch with your actual executable using guiai desktop TARGET --session PROJECT --toolkit tk --agent AGENT_EXECUTABLE. Use --agent-command for custom arguments.

Do not install a model, credentials, or optional analysis extras. Report both versions, installation and project paths, validation results, and the exact launch command. Confirm that the native Windows workbench opens with ConPTY and your real CLI starts inside it.
```

</details>

## CLI only

<details>
<summary><strong>CLI Only Installation Prompt</strong></summary>

This is the explicit installation choice for users who want the Ablation command-line tools **without GUIAI**. The normal Ablation + GUIAI installation includes both by default.

```text
Install only the standard Ablation command-line tools for me, without the GUIAI workbench.

Check for Git and Python 3.10 or newer. Create a project-local virtual environment and activate it for my operating system. For an existing source checkout, verify its origin and preserve uncommitted changes; do not reset, clean, overwrite, or pull over local changes.

Install the standard package with python -m pip install ablation-tool, or from a reviewed source checkout with python -m pip install . Do not run forall.py for this CLI-only installation because its default includes GUIAI.

Keep full, LLM, bytecode, model-provider, credential, and optional analysis extras opt-in. Do not use sudo, global Python installation, alternate package sources, or firmware analysis. Stop on errors.

Verify with ablation --help. Report the checkout and environment paths, Python version, Ablation version, installed extras, and verification result. Do not launch GUIAI or execute the RE target.
```

</details>

For project saving, custom agent arguments, and the native workbench, see the [GUIAI guide](README.md) and [platform package details](packaging/README.md).
