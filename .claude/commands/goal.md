---
description: Drive the IBM-RE Full Collection goal autonomously — pick the next pending target, complete it fully, commit, and continue without stopping for "proceed" prompts.
argument-hint: "[target name — optional, to jump to a specific target]"
---

# /goal — IBM-RE Full Collection autonomous driver

You have been invoked to drive the IBM-RE Full Collection goal without
stopping for "proceed" prompts. Work through the target queue in order
until blocked by something only the user can resolve (missing file,
mount permission, ambiguous verdict).

## Step 1 — read current state

Read both files now before doing anything else:

1. `re/ibm/GOAL_ibm_re.md` — full target list with completion markers
2. `re/ibm/ibm_bomc_re.py` — `TRIAGE_RESULTS['remaining']` list and last SESSIONS entry

Identify the **next unchecked target** in GOAL_ibm_re.md order. If an argument
was passed to `/goal`, jump to that target instead.

## Step 2 — execute the target

Follow the RE workflow from CLAUDE.md exactly:

1. Confirm the binary/image exists (check README Download Status if present).
2. `BinaryContext.load_or_build()` for ELF targets. Raw byte analysis for
   non-ELF targets (SH4 raw, XCOFF, GOFF, EBCDIC, ROM).
3. `SemanticSearcher` sweep before any manual disasm.
4. Taint-trace all exec-class call sites to CONFIRMED / ELIMINATED / CANDIDATE.
5. Byte-verify every CONFIRMED or CANDIDATE verdict before writing it.
6. Write findings to the appropriate `re/ibm/<target>_re.py` module.
   BoMC targets go into `re/ibm/ibm_bomc_re.py`. All others get their own file.
7. `FORGE.audit_module()` — must PASS before commit.
8. Run `python3 -m pytest tests/ -q` — must pass.
9. `git add -f` (re/ is gitignored), commit with Co-Authored-By line, push.

## Step 3 — mark done and continue

After committing:
- Update `re/ibm/GOAL_ibm_re.md`: change `[ ]` to `[x]` for the completed target.
- Remove the target from `TRIAGE_RESULTS['remaining']` in the RE module.
- Update `re/ibm/SESSION_bomc_imm2.md` (for BoMC targets) or the target's
  own session file.
- **Immediately proceed to the next target in the queue. Do not pause.**

## Stop conditions (only these justify stopping)

- The target binary/image is missing from the research drive and cannot be found.
- A tool (BinaryContext, SemanticSearcher) fails with an unhandled architecture
  gap that requires a new ablation module — write the module first, then continue.
- A finding requires a decision about severity or disclosure scope that only
  the user can make.
- Context is approaching 70% capacity — write full state to disk and report.

## Hard rules (always in force)

- `~/ablation/` is never deleted, moved, or destructively modified.
- All ablation edits: main session only. Never fork or delegate.
- After every commit: `env HOME=/home/cowboy GIT_LFS_SKIP_SMUDGE=1 git push origin main`
- Semantic sweep before ANY manual disasm on a new binary or new vuln class.
- Byte-verify every VA before writing CONFIRMED. No exceptions.
- FORGE gate before every commit.
- RE findings go in `re/ibm/<target>_re.py`. Never in `modules/`.
- GitHub: ALL repo ops via `gh` CLI. `mcp__github` is BANNED.
- No Ghidra. Ever.

## Target order (from GOAL_ibm_re.md)

BoMC remaining → Tier 1 (dxexec, IPLROM, cd7200, zOS-IOC, z390-PTFs,
hyper-protect SE, NC-AS400, MQSeries NonStop, pSeries FW ×5, POWER7 FW,
TokenRing ROM, dcconnect 7526/7527) → Tier 2 (HMC squashfs, IBM4690,
VIOS BFF, POWER simulators) → Tier 3 (TWS IRIX, TWS OSF/1).
