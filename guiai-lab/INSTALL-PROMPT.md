# Universal GUIAI install prompt

Paste this prompt into the AI Agent you want to embed. Then type `/forall`. This is a shared instruction for the AI Agent, not a built-in slash command supplied by every CLI. It works through Kimi Code, Claude Code, Codex, and other interactive agents that can download files and run local commands.

```text
When I type /forall, install GUIAI for Ablation and launch it with you—the AI Agent I am currently using—embedded in its terminal.

Ask before privileged commands or system changes. Do not execute the RE target, install an AI model, change credentials, or bypass my permissions. Preserve my existing files and local changes.

1. Check for Python 3.10 or newer with Tkinter. Native Windows requires Python 3.11 x64. On macOS, use a Python distribution that includes Tkinter. On Ubuntu or Debian, ask before installing missing native dependencies:
   sudo apt install python3-venv python3-tk python3-gi python3-cairo python3-gi-cairo gir1.2-gtk-3.0 gir1.2-vte-2.91

2. Download this installer over HTTPS into a new temporary or working directory:
   https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py

   Do not pipe a downloaded script directly into Python. Review it first. It selects the native Windows, macOS, or Linux package, verifies the package against the release's SHA256SUMS.txt, and installs its GUIAI Python dependencies offline. METRIX is bundled. This installs GUIAI, not the optional full Ablation analysis environment, AI models, or agent credentials.

3. Run the reviewed installer with the checked Python:
   python forall.py

   It creates a new installation under the current user's data directory and runs native validation. Do not use sudo. If the destination exists, stop and ask me before choosing another empty directory with --directory; never delete or overwrite my installation. Do not skip failed tests or report an unverified installation as successful.

4. Use the exact guiai executable reported by the installer:
   guiai desktop TARGET --session SESSION --agent AGENT_EXECUTABLE

   On native Windows and macOS, add --toolkit tk. Use the actual executable for this session, commonly kimi, claude, or codex. For custom arguments, use:
   guiai desktop TARGET --session SESSION --agent-command 'AGENT_EXECUTABLE --flag'

   If you cannot identify the executable, ask me instead of substituting another agent. Ask for TARGET and SESSION if I have not provided them. Confirm that the native window opens and the embedded CLI starts, then report the installation directory and exact launch command.
```
