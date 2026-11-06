# Universal OS Installation Prompt

Copy this prompt into your AI Agent. It will ask you to choose **GUIAI** or **CLI Only** before installing anything.

```text
Ask me to choose one installation type and wait for my answer before installing anything:

1. GUIAI — install the standard Ablation CLI and GUIAI, then launch the workbench with you—the AI Agent I am currently using—embedded in its terminal.
2. CLI Only — install the standard Ablation CLI without GUIAI.

Do not continue until I explicitly choose GUIAI or CLI Only.

If I choose GUIAI:
- Check my operating system and Python first. Native Windows requires Python 3.11 x64 with Tcl/Tk; macOS and Linux require Python 3.10 or newer with Tkinter. Explain missing prerequisites and ask before system changes.
- Download and review https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py and run it with the checked Python. Use the default full installation, which includes both Ablation and GUIAI, verifies release checksums, installs GUIAI's wheels offline, and downloads standard Ablation dependencies from PyPI.
- Ask me for the RE target and a project directory outside it. On macOS, open the generated Ablation.app. On Windows and macOS, use --toolkit tk when launching through the CLI. Use your actual executable for the embedded AI Agent; if you cannot identify it, ask me instead of substituting another agent.
- Verify ablation --help and guiai --help, and confirm that the native window opens with your real CLI inside it.

If I choose CLI Only:
- Create a project-local virtual environment and activate it for my operating system. For an existing source checkout, verify its origin and preserve uncommitted changes.
- Install the standard package with python -m pip install ablation-tool, or from a reviewed source checkout with python -m pip install . Do not run forall.py because its default includes GUIAI.
- Verify ablation --help. Do not launch GUIAI.

For either choice:
- Preserve my files and local changes. Do not use sudo, overwrite an existing installation, skip failed validation, or bypass my permissions.
- Do not install an AI model, credentials, optional analysis extras, or firmware analysis. Do not execute the RE target.
- Report my selected option, operating system, Ablation and GUIAI versions when applicable, installation and project paths, validation result, and exact launch command.
```

For manual platform packages, see the [platform package guide](packaging/README.md).
