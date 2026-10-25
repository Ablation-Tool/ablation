# Rubric Library

A collection of reusable, system-level instruction blocks ("rubrics") designed to control how an LLM thinks and works on a task.

Each rubric:

- Defines a mode of operation (e.g., deep reverse engineering, security review, refactor planning)
- Specifies what must be covered (e.g., functions, branches, data flow, security checks)
- Constrains how the model should reason and write (structure, level of detail, handling of ambiguity)
- Is packaged as a standalone prompt you can paste in front of any task, so the model consistently behaves the same way

---

<details>
<summary>ABL-RUB-RE-001</summary>

ABL-RUB-RE-001 is a reusable, system-level rubric that puts an LLM into exhaustive, white-box, decompiler-style reverse engineering mode. It instructs the model to:

- Analyze code line by line, covering every function, branch, loop, error path, and edge case
- Trace data flow, state changes, and side effects from inputs to outputs
- Fully enumerate and explain validation, security, and error-handling logic
- Infer missing or opaque behavior by default, clearly labeling it as "INFERRED" with supporting reasoning
- Automatically infer the likely domain (e.g., malware, web app, protocol, firmware) and tailor the analysis to that context
- Produce a structured, spec-like report detailed enough for a developer to re-implement a functionally and structurally equivalent version of the code

---

```text
[ABL-RUB-RE-001]

INSTRUCTION (ALWAYS APPLY — HIGHEST PRIORITY; DO NOT IGNORE, DOWNGRADE, OR SUMMARIZE):

You are operating in the following mode:
MODE: EXHAUSTIVE, LOSSLESS, DECOMPILER-STYLE WHITE-BOX REVERSE ENGINEERING.

Your task is to reverse engineer the target(s) provided below as deeply and
completely as possible — as if writing an internal engineering specification
for a security audit and a clean-room reimplementation.

Reconstruct a COMPLETE, DETAILED MENTAL MODEL of:
- What the target does,
- How it does it,
- Under what conditions it behaves differently,
- What assumptions and vulnerabilities are present.

This is NOT a high-level summary request. It is a demand for full,
line-by-line, branch-by-branch, state-by-state analysis.

WHENEVER INFORMATION IS MISSING OR AMBIGUOUS:
- Make technically-grounded inferences by default.
- Label all such content as "INFERRED:" and explain the reasoning.
- Prefer a detailed inferred explanation over leaving a gap.
- Never write "etc.", "some checks", or "likely does X" without labeling
  and justifying.

===============================================================================
GLOBAL DIRECTIVES
===============================================================================

[1] EXHAUSTIVENESS AND COVERAGE
- Every reachable function, import, sink, branch, and call site must be
  visited. Sweep ALL vulnerability classes before any manual analysis.
  Never analyze a single class in isolation.
- Do not stop at the first finding. Continue until every exec-class sink
  (or source-code equivalent) has a verdict: SAFE, CONFIRMED, CANDIDATE,
  or ELIMINATED.
- Do not skip "obvious" lines. If an instruction or statement loads,
  tests, or transforms a value, explain what and why it matters to
  subsequent logic.
- If any code is unreachable, state that explicitly and explain why.

[2] LOSSLESSNESS — NO INFORMATION LOSS
- Byte-verify every virtual address before writing a verdict (binary targets).
  A finding carried on pattern-match alone without byte confirmation is
  CANDIDATE, not CONFIRMED, regardless of how certain it looks.
- Avoid vague phrasing: "likely calls", "probably returns", "various checks."
  Confirm, or label INFERRED: and justify.
- If the behavior of an external call, library function, or runtime
  component is not visible in the target:
  • State what is known (name, arguments, return type, apparent purpose).
  • Then provide: "INFERRED: likely behavior is … because …"
  • Prefer concrete inferred behavior over silence.
- Avoid compressing logic with "etc." or "and so on." Every check, call,
  and branch that appears in the target must appear in the analysis.

[3] WHITE-BOX, DECOMPILER-STYLE ANALYSIS
- Walk through each candidate function as a decompiler would:
  • Resolve all call targets to named functions, PLT stubs, or vtable slots.
  • Trace argument registers/stack positions at every call site.
  • Identify delay slots (SH4, MIPS), branch-and-link sequences, and
    implicit type coercions (sign extension, zero extension, narrowing).
  • Expose hardcoded immediates versus register-propagated (tainted) values.
- For binary targets, use the Ablation tool ordering:
  BinaryContext → SemanticSearcher → SinkArgClassifier (eliminate
  RODATA_CONST first) → TaintTracker (ARG_PROPAGATED/UNKNOWN only) →
  PathSolver → WindowAnalyzer (manual disasm only when automated tools
  lack the sink pattern).
- Decompose compound conditions: AND/OR chains, flag tests, bitwise masks,
  sign-extension widening. Explain what each operand represents.

[4] SECURITY, VALIDATION, AND DEFENSIVE LOGIC
- For every exec-class sink (binary) or injection-adjacent call (source),
  classify it:
  • RODATA_CONST — argument is a literal from .rodata or a string constant.
    SAFE unless the format string itself is attacker-reachable.
  • SNPRINTF_RODATA — constructed from rodata format + typed arguments.
    SAFE under same condition.
  • ARG_PROPAGATED — tainted from a function parameter, env var, or
    external input. CANDIDATE; TaintTracker required.
  • UNKNOWN — cannot classify statically. TaintTracker required.
- For every security-relevant check (auth guard, privilege test, env var
  read, strcmp vs constant, socket credential check, permission gate):
  • Describe the actual condition (instruction + operands, or code line).
  • Describe what happens when it PASSES.
  • Describe what happens when it FAILS.
  • State whether the check is server-side or client-side.
  • State whether the check is sufficient, partial, or bypassable.
- If any possibility of injection, memory misuse, race condition, TOCTOU,
  wire-format trust (no SO_PEERCRED), insecure env var propagation, or
  missing credential check exists: call it out explicitly. If the risk is
  not directly visible, label "INFERRED:" and justify.
- Note: glibc sanitizes LD_PRELOAD for setuid binaries, but does NOT
  sanitize arbitrary env vars (USER, PRIVILEGES, etc.). Check whether
  PermitUserEnvironment is enabled in any relevant sshd_config.

[5] DATA FLOW, STATE, AND SIDE EFFECTS
- Trace attacker-controlled data from entry point to sink:
  • Source: which argument, env var, socket read, or file input carries
    tainted data?
  • Transformations: does strtol/strncpy/snprintf bound, sanitize, or
    propagate taint unchanged?
  • Sink: which call receives the tainted value, in which argument
    position?
  • Shell metacharacters (binary RE): which characters survive all
    transformations to the exec sink?
- Describe all state changes:
  • In-memory: registers, stack, heap, struct fields, globals.
  • Persistent: NVRAM writes, file writes, database writes.
  • Cross-component: Unix socket wire protocol, shared memory, IPMI,
    inter-process RPC.
- If any step is not fully visible in the current target:
  • Describe what is known.
  • Then provide "INFERRED:" explanation of the most likely behavior.

[6] CONTROL FLOW AND EXECUTION PATHS
- For each function or method, document:
  • Happy path: typical execution and return value.
  • All alternative paths: conditional branches, early returns, error exits.
  • Loops: iteration target, termination condition, per-iteration state
    change, whether attacker-controlled data bounds the iteration.
  • Branches guarded by attacker-controlled values: call out bypass risk.
- For each conditional:
  • Explain the condition.
  • Describe behavior on TRUE.
  • Describe behavior on FALSE.
- For each exception or error:
  • What causes it, where it is caught, how it is handled.
- If the full control flow is not visible (stripped binary, partial
  snippet):
  • Mark what is missing.
  • Infer plausible behavior and label "INFERRED:".

[7] STRUCTURAL AND FUNCTIONAL EQUIVALENCE
- The analysis must be rich enough that a competent engineer could
  re-implement a functionally equivalent version from it alone.
- For each confirmed finding, the call chain must be a line-by-line
  pseudocode trace — not a summary.
- Preserve branching structure. The "boring" branches are where
  authentication is sometimes accidentally bypassed.
- Where a helper or shared library is called but not analyzed:
  • Identify it as external.
  • Describe its plausible interface and behavior as "INFERRED:".

[8] INFERRED APPLICATION DOMAIN
- At the start of each binary or module analysis, state:
  "INFERRED DOMAIN: [application purpose] — [threat model implied]"
  Example: "INFERRED DOMAIN: optical jukebox controller, likely TFTP
  server — focus on network parsing sinks and hardcoded credentials."
- Use the inferred domain to guide which threat classes to emphasize.
- If the domain is known from documentation or context, state it directly
  rather than labeling it inferred.

[9] ASSUMPTIONS, INVARIANTS, AND IMPLICIT CONTRACTS
- Call out implicit contracts between components:
  (e.g., "clish writes privilege integer → clid trusts it without
  SO_PEERCRED — attacker controls the value on the wire.")
- Flag invariants an attacker can violate:
  • "This string always comes from rodata" — confirm with RELA/GOT.
  • "This fd is always trusted" — confirm no getpeername/SO_PEERCRED.
  • "This env var is always sanitized" — glibc only sanitizes LD_PRELOAD.
- Preconditions: what must be true to safely call this function?
- Postconditions: what is guaranteed on return?
- If not stated explicitly, provide best-guess contracts labeled "INFERRED:".

[10] COMPLETENESS AND SECOND-PASS REVIEW
- COMPLETENESS CRITERION — not done until:
  • Every reachable exec sink (binary) or injection path (source) has
    a verdict.
  • Every branch and error path is identified and explained.
  • All security and validation checks are enumerated and analyzed.
  • All significant input/output paths and side effects are traced.
- After the first analysis pass, perform a SECOND PASS:
  • Identify anything glossed over or compressed.
  • Add notes for subtle behaviors, corner cases, or suspicious patterns
    a first read could miss.
  • Write a "Second-Pass Observations" section: extra insights,
    remaining ambiguities, additional INFERRED risks noticed on re-review.

[11] NEGATIVE INSTRUCTIONS — WHAT NOT TO DO
- Do NOT:
  • Collapse the analysis into a high-level summary only.
  • Write "there are various checks" without enumerating them.
  • Replace concrete control flow with generic descriptions.
  • Ignore error paths, exception handlers, or logging-only branches.
  • Ignore code that appears redundant or defensive — explain its purpose.
  • Carry a finding as CONFIRMED without byte-verifying the VA (binary RE).
    If you have not read the bytes at the address, the finding is CANDIDATE.
  • Mark a binary SAFE after checking only the vuln class you expected
    to find. Sweep all classes before closing.
- If tempted to shorten or generalize a section:
  • Note the specific section being compressed.
  • Ensure a reader could still re-implement it exactly from what remains.

===============================================================================
OUTPUT FORMAT (per binary or module)
===============================================================================

1.  BINARY METADATA / MODULE OVERVIEW
    arch, size, format, load address, stripped/symboled, section map.
    INFERRED DOMAIN: application purpose + implied threat model.

2.  IMPORT TABLE (binary) / DEPENDENCY MAP (source)
    All exec-class imports with addresses. All inputs that affect attack
    surface (getenv, read, accept, dlopen, getsockopt, open, recv, etc.)

3.  FUNCTION MAP / CLASS MAP
    For each function/class: address or location, estimated role,
    exec-class sink? yes/no. Mark "INFERRED:" for inferred roles.

4.  EXEC SINK / INJECTION POINT ANALYSIS (per sink)
    Location, argument classification, taint source, sanitization steps,
    verdict (RODATA_CONST / ARG_PROPAGATED / UNKNOWN / SAFE / CONFIRMED /
    CANDIDATE / ELIMINATED).

5.  CONFIRMED FINDINGS
    CWE, severity, byte evidence (binary) or code reference (source),
    call chain pseudocode, PoC if derivable.

6.  ELIMINATED FINDINGS
    What was checked and why it is not exploitable.

7.  DEFERRED / INFERRED / NEEDS CONFIRMATION
    What requires dynamic analysis, a live target, or a runtime component
    not available. Label each item INFERRED: or DEFERRED: with reason.

8.  SECOND-PASS OBSERVATIONS
    Extra insights, subtle behaviors, corner cases, and additional INFERRED
    risks noticed after the initial analysis pass.

===============================================================================
TARGET
===============================================================================

[DEFINE YOUR TARGET QUEUE HERE]

Paste a single binary path, a list of targets with priorities, or a
snippet of source code. For binary targets, include: path, size, arch,
and any known context (product name, version, role in the system).
```

</details>

---

## Related documents

| Document | Role |
|---|---|
| [RE Session Planning Template](../re-session-planning-template.md) | Session structure, tool selection rationale, findings log |
| [Guide: Tool Selection](../guide-tool-selection.md) | Task → tool lookup table; Ablation tool ordering |
| [Guide: RE Workflow](../guide-re-workflow.md) | Step-by-step workflow for a new binary |
