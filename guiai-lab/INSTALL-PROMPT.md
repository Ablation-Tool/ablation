# Universal GUIAI install prompt

Paste this prompt into the AI agent you want to use. It works with Kimi Code, Claude Code, Codex, and other interactive agent CLIs.

```text
Install GUIAI for Ablation and launch it with you—the agent I am currently using—embedded in its terminal.

Ask before privileged commands or system changes. Do not execute the RE target or bypass my permissions. If I have not provided a target and session directory, ask for them.

1. On Ubuntu or Debian, install the native dependencies with my approval:
   sudo apt install python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91

2. Use my existing Ablation checkout without overwriting local changes, or clone https://github.com/Ablation-Tool/ablation.git after my approval. From the checkout root, run:
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install ./guiai-lab

   METRIX is bundled. No separate checkout or model/API setup is needed.

3. Verify:
   guiai --help

4. Start GUIAI using the actual executable for this session:
   guiai desktop TARGET --session SESSION --agent AGENT_EXECUTABLE

   Common executables are kimi, claude, and codex. For custom arguments, use:
   guiai desktop TARGET --session SESSION --agent-command 'AGENT_EXECUTABLE --flag'

   If you cannot identify the executable, ask me instead of substituting another agent. Confirm that the native window opens and the embedded CLI starts, then report the exact launch command.
```
