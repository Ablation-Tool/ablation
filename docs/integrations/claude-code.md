# Using Ablation with Claude Code

Ablation and Claude Code are complementary: Ablation handles the scale problem
(finding candidates across thousands of stripped functions in seconds), and Claude
handles the interpretation problem (tracing taint paths, explaining CFG structure,
assessing exploitability). Neither replaces the other -- together they cover the
full loop from initial scan to confirmed finding.

---

## The basic loop

From any Claude Code session, prefix Ablation CLI commands with `!` to run them
inline and pipe the output directly into the conversation:

```bash
! ablation corpus /path/to/firmware.so --product my-target --version 1.0
! ablation sweep  /path/to/firmware.so
! ablation search /path/to/firmware.so "parser reads user-controlled length field"
```

Claude reads the output and can immediately follow up:

- "The sweep returned `fn_0x1fa00` at score 0.71 for `strcpy with user-controlled src`.
  Run `ablation cfg /path/to/firmware.so 0x1fa00 --insns` to get the CFG."
- "I see `fn_0x2200c` calling into `fn_0x1fa00`. That call chain is worth tracing."

---

## Recommended CLAUDE.md setup

Add this to your project's `CLAUDE.md` to give Claude Code persistent context about
the target and available commands:

```markdown
## Firmware RE session

Target binary: /path/to/firmware.so
Corpus DB:     ~/.ablation/func_id.db

## Available tools

Run with ! prefix from any prompt:

- ablation corpus <binary> [--product X] [--version Y] [--sigs]
- ablation sweep  <binary> [--json out.json] [--sarif out.sarif]
- ablation search <binary> "<query>" [--top-k N]
- ablation taint  <binary>
- ablation cfg    <binary> <hex-va> [--insns]
- ablation sigs   <binary> [--dry-run]
- ablation findings [--json F] [--sarif F]

## Workflow

1. corpus -- build behavioral fingerprints for all functions
2. sweep  -- run all 30 vuln-class patterns; review candidates
3. search -- targeted query for specific behavior
4. cfg    -- get CFG + instructions for top candidates
5. taint  -- trace network inputs to dangerous sinks
```

---

## Typical research session

**Step 1 -- Build corpus (one time per binary)**

```
! ablation corpus firmware.so --product my-target --version 2.1 --sigs
```

Output: function count, DB path, and count of auto-named functions. Claude confirms
the build and notes how many functions are named vs unnamed.

**Step 2 -- Sweep all vuln classes**

```
! ablation sweep firmware.so
```

Output: one line per pattern hit above the score threshold. Claude ranks the highest-
confidence candidates, groups them by vuln class, and suggests which to trace first.

**Step 3 -- Targeted search**

```
! ablation search firmware.so "length field from packet header controls malloc size"
```

Output: top-k matches with VAs and scores. Ask Claude to explain why each candidate
scores high and which are worth CFG inspection.

**Step 4 -- CFG and taint**

```
! ablation cfg firmware.so 0x1fa00 --insns
! ablation taint firmware.so
```

Claude interprets the CFG output: identifies loop back-edges, locates the dangerous
call, traces argument provenance, and estimates reach from network input.

**Step 5 -- Export findings**

```
! ablation findings --json session_findings.json
! ablation sweep firmware.so --sarif pr_annotations.sarif
```

---

## What Claude does well here

| Task | Who does it |
|---|---|
| Finding candidates across 10,000+ functions | Ablation (sweep, search) |
| Ranking by behavioral similarity | Ablation (BERT cosine score) |
| Explaining why a function matches a pattern | Claude |
| Tracing taint across multiple functions | Ablation (taint) + Claude interpretation |
| Deciding if a finding is exploitable | Claude (from CFG + insns output) |
| Writing the disclosure section | Claude |
| Cross-version diffing to confirm regression | Ablation (cross-version workflow) |

---

## Tips

- Pass `--top-k 20` to `ablation search` to give Claude more candidates to reason over.
- Pipe long outputs to a file and then `Read` it: `! ablation sweep fw.so > /tmp/sweep.txt`
  then ask Claude to analyze `/tmp/sweep.txt`.
- After Claude identifies a likely finding, confirm it with
  `ablation cfg <binary> <va> --insns` and paste the output back.
- Use `ablation sigs firmware.so --dry-run` to preview function naming before committing.

---

## MCP server (coming soon)

A structured MCP server wrapping all Ablation commands is planned. It will allow
Claude Code to invoke Ablation as a tool with structured input/output rather than
parsing CLI text. Track progress in [GitHub Issues](https://github.com/Ablation-Tool/ablation/issues).
