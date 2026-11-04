# Terminal

## Purpose

The GEM terminal embeds the user's actual interactive CLI beside the investigation Lab. It is a real terminal, not a chatbot transcript or a model built into the application. The user can inspect output, answer agent prompts, approve commands, and continue analysis without moving between windows.

## Native implementations

- **Linux GTK:** native VTE with independent terminals for each Lab.
- **Tk:** `TerminalPanel` with `pyte` parsing and a POSIX PTY on Linux and macOS.
- **Native Windows:** the same Tk panel backed by ConPTY rather than WSL.
- **macOS:** `GEM.app` starts the Tk workbench with a POSIX PTY from its bundled Python environment.

The terminal sets `TERM=xterm-256color`, `COLORTERM=truecolor`, the session environment, and the appropriate package path. It forwards ordinary and shifted keys, editing keys, arrows, function keys, clipboard input, and Unicode input to the child process.

## Display and preferences

The display handles terminal control sequences, cursor movement, colors, reverse video, bold, italics, underline, and strike-through. It supports scrollback and resizing while preserving the child CLI's interactive state.

Preferences include the configured system monospace font, Ubuntu/system, Tango, Linux console, XTerm, Solarized dark/light, high-contrast, and custom schemes. Foreground, background, and all 16 ANSI palette entries can be edited. Font and color settings persist in the root `preferences.json`.

Clipboard paste is bounded to 8 MiB and reports a rejection rather than silently truncating an oversized paste. Mouse and keyboard focus are preserved where the native toolkit supports them.

## Process input and output

POSIX children run under a new terminal and process group. Output is read without blocking the Tk event loop, then fed through `pyte` into the visible screen. ConPTY output is read on a daemon thread and delivered through a queue to the GUI thread.

Writes preserve ordering through a queue that handles partial and temporarily blocked writes. Resize events update both the visible screen and the child terminal's reported dimensions.

When a child exits, the terminal drains available output before marking the session closed. ConPTY shutdown waits for both process exit and reader end-of-stream so final lines are not lost.

## Closing and recovery

Closing a tab or application cancels delayed starts and scheduled callbacks, signals the child process group, waits briefly, and escalates stubborn children when required. POSIX children are reaped using nonblocking `waitpid`; Windows children are checked through their process object.

The embedded terminal reports startup failures, read/write failures, parser warnings, and process exit status through the workspace status area. It does not hide a failed agent launch behind a fake successful CLI prompt.

## Typical workflow

1. Launch GEM with `--agent` or `--agent-command`.
2. Select a Lab node and use **Open in CLI** or copy a focused prompt.
3. Interact with the real CLI, including its own authentication or permission prompts.
4. Record discoveries through `gem emit` or `gem emit-many`.
5. Close the tab or application when finished; the event history remains saved even though the live terminal stops.

## Implementation map

- `gem-lab/metrix/desktop.py`: Tk terminal, PTY/ConPTY I/O, rendering, keyboard input, resizing, and cleanup
- `gem-lab/gem/gtk_app.py`: native VTE creation and agent lifecycle
- `gem-lab/gem/environment.py`: session and agent environment
- `gem-lab/gem/preferences.py`: font, color scheme, and ANSI palette persistence

## Limits and validation

The terminal does not provide the model or its credentials. Full-screen interfaces, authentication flows, and terminal-specific control sequences vary by agent and may require compatibility testing.

Validation covers interactive PTY startup and input, ConPTY interactive input, forced cleanup, output draining, partial writes, resize handling, oversized paste rejection, delayed-start cancellation, and repeated shutdown. The desktop workflow additionally checks focus, shifted keys, Unicode, clipboard operations, and real CLI state.
