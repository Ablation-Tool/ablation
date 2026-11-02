# Installation Prompt

Copy the Installation Prompt into your AI Agent. It detects your operating system and installs **Ablation and GUIAI together by default**. Choose **CLI only** only if you do not want GUIAI.

<details>
<summary><strong>Installation Prompt</strong></summary>

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
<summary><strong>CLI only</strong></summary>

Use this prompt only when you want the Ablation command-line tools **without GUIAI**. The normal installation includes both by default.

```text
Install only the standard Ablation command-line tools for me, without the GUIAI workbench.

Check for Git and Python 3.10 or newer. Create a project-local virtual environment and activate it for my operating system. For an existing source checkout, verify its origin and preserve uncommitted changes; do not reset, clean, overwrite, or pull over local changes.

Install the standard package with python -m pip install ablation-tool, or from a reviewed source checkout with python -m pip install . Do not run forall.py for this CLI-only installation because its default includes GUIAI.

Keep full, LLM, bytecode, model-provider, credential, and optional analysis extras opt-in. Do not use sudo, global Python installation, alternate package sources, or firmware analysis. Stop on errors.

Verify with ablation --help. Report the checkout and environment paths, Python version, Ablation version, installed extras, and verification result. Do not launch GUIAI or execute the RE target.
```

</details>

For project saving, custom agent arguments, and the native workbench, see the [GUIAI guide](README.md) and [platform package details](packaging/README.md).
