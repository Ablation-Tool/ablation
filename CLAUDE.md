# Ablation -- Claude Code reference

Ablation is a Python framework for semantic firmware analysis. This file gives Claude
Code the context to use it effectively within a RE session.

---

## CLI commands

All commands are available after `pip install git+https://github.com/Ablation-Tool/ablation`.

```
ablation corpus  <binary> [--product X] [--version Y] [--sigs] [--db PATH]
ablation sweep   <binary> [--json FILE] [--sarif FILE] [--min-score N] [--db PATH]
ablation search  <binary> <query>       [--top-k N]   [--db PATH]
ablation taint   <binary>
ablation cfg     <binary> <hex-va>      [--insns]
ablation crypto  <binary>
ablation sigs    <binary>               [--dry-run]   [--db PATH]
ablation findings                       [--json FILE] [--sarif FILE]
ablation analyze <binary>
```

Run with `!` prefix from any Claude Code prompt to inline the output into the session.

---

## Standard workflow

```
corpus → sweep → search → cfg → taint → findings
```

1. **corpus** -- build behavioral fingerprints for every function in the binary (~30s
   for a 19,000-function binary on CPU). Add `--sigs` to auto-name stripped functions.

2. **sweep** -- run all 30 vulnerability patterns against the corpus. Returns candidates
   with cosine similarity scores. Covers: buffer overflow, heap overflow, cmd-exec,
   format string, integer overflow, UAF, double-free, race condition, DoS, info-leak,
   auth-bypass, crypto misuse, path traversal, timing side-channel.

3. **search** -- targeted query for a specific behavior. More precise than sweep when
   you already know what you are looking for.

4. **cfg** -- control-flow graph for a candidate VA. Use `--insns` to include
   disassembly. Reveals loop structure, call targets, and argument provenance.

5. **taint** -- traces user-controlled data from network read functions to dangerous
   sinks (memcpy, system, execve, etc.).

6. **findings** -- lists all confirmed findings stored in the local findings DB.
   Export with `--sarif` for GitHub Code Scanning.

---

## Key paths

| Path | Purpose |
|---|---|
| `~/.ablation/func_id.db` | Default corpus DB (SQLite) |
| `~/.ablation/patterns.json` | Registered sweep patterns (auto-updated) |
| `~/.ablation/sig_cache/` | Cached BERT embeddings for signature matching |

---

## Output interpretation

**sweep output** -- one line per pattern hit:

```
[buffer-overflow] strcpy with user-controlled src (score=0.71)  va=0x1fa00  fn_0x1fa00
```

Score >= 0.5 is worth manual inspection. Score >= 0.65 is a strong behavioral match.

**search output** -- ranked list of functions:

```
0x1fa00  fn_0x1fa00      copies fixed buffer from config string    score=0.834
0x21004  parse_field     reads length prefix and advances pointer  score=0.791
```

**cfg output** -- basic blocks with optional disassembly. Look for:
- Loops where the bound comes from a packet field
- `call` to sink functions with arguments sourced from earlier `mov` from network buffer
- Error paths that skip bounds checks

---

## Example session

```bash
! ablation corpus   /firmware/target.so --product my-target --version 2.1 --sigs
! ablation sweep    /firmware/target.so --json /tmp/sweep.json
! ablation search   /firmware/target.so "parses TLV field, advances pointer without bound check"
! ablation cfg      /firmware/target.so 0x1fa00 --insns
! ablation taint    /firmware/target.so
! ablation findings --sarif /tmp/findings.sarif
```

---

## Adding the target binary

Before running `sweep` or `search`, the corpus must be built:

```bash
! ablation corpus /path/to/binary.so --product <target-name> --version <version>
```

This writes to `~/.ablation/func_id.db`. Subsequent commands read from there.
Use `--db /tmp/custom.db` to isolate a corpus for a specific engagement.
