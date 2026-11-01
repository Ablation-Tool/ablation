# GUIAI Prompt Install

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

For manual platform instructions or installation without GUIAI, see the [all-platform installation guide](INSTALL.md).
