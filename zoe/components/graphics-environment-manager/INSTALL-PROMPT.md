# Universal OS Installation Prompt

> Canonical master reference. For this standalone repository, use the installation steps in [README.md](README.md); the prompt below is preserved with the master packaging sources.

Copy this prompt into your AI Agent. It will ask you to choose **GEM** or **CLI Only** before installing anything.

```text
Ask me to choose one installation type and wait for my answer before installing anything:

1. GEM — install the standard Ablation CLI and GEM, then launch the workbench with you—the AI Agent I am currently using—embedded in its terminal.
2. CLI Only — install the standard Ablation CLI without GEM.

Do not continue until I explicitly choose GEM or CLI Only.

If I choose GEM:
- Check my operating system and Python first. Native Windows requires Python 3.11 x64 with Tcl/Tk; macOS and Linux require Python 3.10 or newer with Tkinter. Explain missing prerequisites and ask before system changes.
- Download and review https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py and run it with the checked Python. Use the default full installation, which includes both Ablation and GEM, verifies release checksums, installs GEM's wheels offline, and downloads standard Ablation dependencies from PyPI.
- Open GEM and choose the RE target inside the application; the session is created automatically outside the target. On macOS, open the generated GEM.app. On Windows and macOS, use --toolkit tk when launching through the CLI. Use your actual executable for the embedded AI Agent; if you cannot identify it, ask me instead of substituting another agent.
- Verify ablation --help and gem --help, choose a target in GEM, and confirm that the workbench opens with your real CLI inside it. Select an artifact, ask the agent to begin working on the selected item, and verify that it reads the current GEM selection and records an evidence-backed status update visible in the Lab; do not treat terminal startup alone as proof of integration.
- If I explicitly do not want a Desktop shortcut, use python forall.py --no-desktop-shortcut. Otherwise, confirm that the installed icon opens GEM directly with in-app Open binary and Open directory actions, stable per-target sessions, installed Kimi, Claude, or Codex CLI detection when available, and the GEM session and workspace environment supplied to its embedded terminal. Use gem launch --no-agent only when I explicitly want the investigation tree without an agent. Dropping local files or folders into the embedded CLI inserts quoted paths without pressing Enter; never execute an RE artifact merely to validate it.
- The turned-A logo exposes **a11y Optimization**, **OS Optimization**, and **Debug**. Each provides a read-only audit with visible findings and proposed commands before requesting permission; Deny must do nothing, and Allow may send only the displayed bounded request to the active AI agent. Accessibility includes persistent colorblind-safe and high-contrast palettes, descriptive labels, text alternatives, and keyboard navigation. Do not claim screen-reader or accessibility compliance without testing with the user's assistive technology.

If I choose CLI Only:
- Create a project-local virtual environment and activate it for my operating system. For an existing source checkout, verify its origin and preserve uncommitted changes.
- Install the standard package with python -m pip install ablation-tool, or from a reviewed source checkout with python -m pip install . Do not run forall.py because its default includes GEM.
- Verify ablation --help. Do not launch GEM.

For either choice:
- Preserve my files and local changes. Do not use sudo, overwrite an existing installation, skip failed validation, or bypass my permissions.
- Do not install an AI model, credentials, optional analysis extras, or firmware analysis. Do not execute the RE target.
- Report my selected option, operating system, Ablation and GEM versions when applicable, installation and project paths, validation result, and exact launch command.
```

For manual platform packages, see the [platform package guide](packaging/README.md).
