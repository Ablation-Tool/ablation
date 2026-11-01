# Universal GUIAI install prompt

Paste this entire prompt into the AI coding agent you want to use. The same prompt works for Kimi Code, Claude Code, Codex, or another interactive agent CLI. The agent must already be installed and configured; GUIAI does not provide a model, account, API key, or authentication.

```text
Install GUIAI for Ablation and launch it with you—the AI agent I am currently using—embedded in its native terminal.

Use my actual interactive CLI, not a different agent, a simulated chatbot, or a hidden API. GUIAI is only the workspace and terminal bridge; you remain the agent. Do not execute the reverse-engineering target, read credentials, or bypass my filesystem, sandbox, or permission settings.

Before any network download, privileged command, or system-package change, tell me what you need and follow my approval. If I have not supplied an RE target and session directory, ask me for them before launching. If the platform is unsupported, stop and explain what is missing instead of silently substituting another interface or agent.

1. Check the environment:
   - Linux with an X11 display and POSIX PTY support.
   - Python 3.10 or newer.
   - GTK3 and VTE for the native interface. On Ubuntu/Debian the packages are:
     python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91
   - Tkinter is optional for the fallback interface.

2. Locate or obtain the Ablation checkout:
   - If an Ablation checkout already exists, use it without overwriting local changes.
   - Otherwise, after my approval, clone:
     https://github.com/Ablation-Tool/ablation.git
   - Change into the checkout's root directory.

3. Create or reuse a virtual environment, then install GUIAI from the checkout:
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install ./guiai-lab

   This installs GUIAI and its bundled METRIX support package. No separate METRIX checkout is required. Install the full Ablation CLI separately only if I want analysis through it:
   python -m pip install -e .

4. Verify the installation:
   guiai --help
   python -m metrix --help

5. Determine the command that starts you interactively. Common executable names are:
   - Kimi Code: kimi
   - Claude Code: claude
   - Codex: codex

   Use the actual executable for this session; do not guess or substitute another agent. If you cannot determine it, ask me or give me the launch command instead of claiming success.

6. Launch with my target and a session directory outside a directory target:
   guiai desktop /path/to/target --session /path/to/session --toolkit gtk --agent AGENT_EXECUTABLE

   For an agent requiring custom arguments, use argument-based parsing without a shell:
   guiai desktop /path/to/target --session /path/to/session --toolkit gtk --agent-command 'AGENT_EXECUTABLE --flag'

   If a separate working directory is useful, add:
   --workspace /path/to/working-directory

7. Report the checkout, virtual environment, session directory, terminal working directory, and exact agent command. Do not claim the integration works until the native window opens and the embedded CLI starts successfully. Leave trust prompts and other permission decisions to me.
```

GUIAI accepts any executable name through `--agent`. Use `--agent-command` when the agent needs arguments. Agent authentication, permissions, trust prompts, provider data policy, and terminal compatibility remain the responsibility of the selected CLI and user.
