# Binary Ninja Plugin

The Ablation plugin for Binary Ninja annotates functions automatically from a pre-built
corpus, runs pattern sweeps from within the disassembler, and lets you query the corpus
in plain English without leaving Binary Ninja.

---

## Installation

1. Copy `ablation/integrations/binja_plugin.py` to your Binary Ninja plugins directory:

   | Platform | Path |
   |---|---|
   | macOS | `~/Library/Application Support/Binary Ninja/plugins/` |
   | Linux | `~/.binaryninja/plugins/` |
   | Windows | `%APPDATA%\Binary Ninja\plugins\` |

2. Restart Binary Ninja.

3. Verify the ablation package is importable from Binary Ninja's Python console:
   ```python
   import ablation
   print(ablation.__version__)
   ```

   If that fails, install ablation into the same Python environment Binary Ninja uses:
   ```bash
   /path/to/binaryninja/python3 -m pip install git+https://github.com/Ablation-Tool/ablation
   ```

---

## Commands

Three commands appear under **Tools > Ablation** and in the command palette:

### Annotate from Corpus

Runs automatically when a binary is opened. Checks `~/.ablation/func_id.db` for a
corpus entry matching the binary's SHA-256. If found, renames matched functions
(e.g., `fn_0x1d700` becomes `likely:memcpy`) and adds `Ablation-Sig` tags.

To trigger manually: **Tools > Ablation > Annotate from Corpus**.

### Sweep Binary

Runs the full PatternLibrary sweep against the open binary. Results appear as
bookmarks with score annotations (e.g., `[buffer-overflow 0.71]`). The sweep builds
a temporary corpus in `/tmp/ablation_binja_<stem>.db` -- it does not write to your
research corpus at `~/.ablation/func_id.db`.

### Semantic Search

Prompts for a plain-English query, then navigates to the highest-scoring matching
function. Useful for quickly locating a specific function type when you know its
behavior but not its name.

---

## Workflow

The typical workflow when opening a new binary:

```
Open binary in Binary Ninja
       |
       v
Plugin checks ~/.ablation/func_id.db
       |
  Found?   --- Yes ---> Renames fn_0x* functions automatically
       |
      No
       |
       v
Tools > Ablation > Sweep Binary   (builds temp corpus, runs 30 patterns)
       |
       v
Review bookmarked candidates
       |
       v
Tools > Ablation > Annotate from Corpus   (if corpus was built externally via CLI)
```

For large targets, build the corpus with the CLI first (faster, progress bar):

```bash
ablation corpus firmware.so --product my-target --sigs
```

Then open the binary in Binary Ninja -- the plugin picks up the pre-built corpus.

---

## Tags

The plugin creates two tag types:

| Tag | Meaning |
|---|---|
| `Ablation-Sweep` | Function matched a vulnerability pattern; score in tag text |
| `Ablation-Sig` | Function renamed via signature matching |

---

## Notes

- The plugin uses a temporary DB for sweeps (`/tmp/ablation_binja_<stem>.db`) so it
  never pollutes your main research corpus.
- Sweep results are not written to `~/.ablation/func_id.db`. To persist them, run
  `ablation corpus` from the CLI.
- The BERT model loads on first use (~3s). Subsequent sweeps are fast.
