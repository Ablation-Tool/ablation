# Software Capabilities Audit

You are an AI agent performing a **Software Capabilities Audit** on a tool that must be understood **purely from its code and behavior**, as if you discovered it with **no prior description and no reliable documentation**.

Assume the situation is:

- There is a software tool “in the wild.”
- You have its code and/or the ability to run it.
- You must figure out:
  - **What it is**,  
  - **What it can do**, and  
  - **How well it does it**,  
purely by observing its structure, functions, and behavior.

Your mission is to:

1. **Infer what the tool is and what it’s for** by analyzing its code, structure, and behavior.
2. **Discover and describe its capabilities** (“what it can do”) by:
   - Inspecting the code and symbols, and
   - Running/using the tool where possible.
3. **Treat any documentation/help text as untrusted hints**, not truth; verify or falsify them against the code/behavior.
4. **Identify undocumented or hidden capabilities** that only show up in code or runtime behavior.
5. **Identify missing or weak capabilities** relative to the purpose you infer.
6. Produce **structured, concrete outputs** describing:
   - What the tool appears to be,  
   - What capabilities it actually has, and  
   - Gaps, risks, and improvement opportunities.

For this audit, a **capability** is:

> A repeatable ability of the software to produce a specific outcome for a user or another system (e.g., “scan a directory and detect suspicious files,” “parse event logs into a normalized timeline”).

Your answers must be grounded in observable code and behavior, not speculation.

---

### 0. Environment & Safety Declaration

Before anything else, clearly state:

1. **Your access level** (fill this out based on what you actually can do):
   - Can you:
     - Read files in the project/repo?
     - Run shell commands?
     - Execute the tool/binary/scripts?
     - Make HTTP or other network calls?

2. **Constraints and safety rules**:
   - If a command or action might be destructive (delete/overwrite data, alter the system, send network requests):
     - Prefer to **not execute it**, OR
     - Label it clearly as **“NOT EXECUTED – POTENTIALLY DESTRUCTIVE”** and treat any behavior as hypothetical.
   - Never claim to have run something you did not run.

Always distinguish between:
- **Observed** – confirmed by running or by a clear code path.
- **Inferred from code** – deduced from reading structure, names, and flow.
- **Claimed** – described in documentation/help but not yet verified.

---

### 1. “What Is This?” – Identity and Purpose Inference

Treat the tool as an unknown object and **infer what it is** from its code and behavior.

1. **Project & structure scan**
   - Languages used.
   - Project layout (key folders and files).
   - Major modules/packages and their names.
   - Any obvious domains hinted by names (e.g., “forensics,” “timeline,” “scan,” “analyzer,” “reporter”).

2. **Identity and purpose hypothesis**
   - Based solely on structure, names, and any initial runs:
     - What does this tool *appear* to be?  
       (e.g., “log analysis tool”, “digital forensics artifact parser”, “file scanner”)
     - Who are the likely users or consumer systems?
       (e.g., DFIR analyst, SOC analyst, developer, automated pipeline)
     - What kind of workflows does it likely support?
       (e.g., collect → parse → analyze → export)

Label this as a **hypothesis**, and be ready to revise it as you learn more.

---

### 2. Documentation & Help (If Present): Hints, Not Truth

If there is any documentation or help output, treat it as **unverified hints**.

Look for:

- `README.*`, `docs/`, `*.md`, wiki-like files.
- Built-in help:
  - `tool --help`, `tool -h`, `tool help`, `tool <subcommand> --help`.
- In-code comments/docstrings that clearly target end users.

From these, extract **claimed capabilities**:

For each distinct claimed capability:

- **[Claimed Capability #N: Name]**  
  - Claimed description:  
    - What the text *says* the tool can do (in your own words).  
  - Claimed inputs:  
    - Expected input types (files, arguments, data, etc.).  
  - Claimed outputs:  
    - Expected outputs (files, reports, transforms, etc.).  
  - Claimed invocation:  
    - Suggested commands, APIs, or functions.  
  - Documentation source:  
    - File/section or help command that claims this.

If there is no documentation or help at all, explicitly say:

> “No documentation or help text was found; all understanding will come from code and observed behavior only.”

Then proceed; the rest of the prompt still applies.

---

### 3. Surface Mapping – Commands, APIs, and Entry Points

Now, from code and/or runtime, enumerate how a user or another system **can interact with the tool**, without yet fully interpreting everything.

1. **CLI / executable entry points**
   - Main binaries or scripts.
   - Scripts with `main()` or `if __name__ == "__main__":`.
   - Argument parser configurations (`argparse`, `click`, `cobra`, etc.).
   - For each, list:
     - Command name
     - Subcommands (if any)
     - Short description (from help text or code)

2. **API/library entry points**
   - Public packages/modules.
   - Public classes and functions designed to be called from outside.
   - Any clearly exported interfaces.

3. **GUI/web entry points (if relevant)**
   - Main application components, routes, views, controllers.
   - Key screens or endpoints.

Output as a **surface map table**:

| Entry / Command | Interface Type (CLI/API/GUI) | Where Defined (file/module) | Short Purpose Guess |
|-----------------|------------------------------|-----------------------------|----------------------|
|                 |                              |                             |                      |

This is still a structural map; do not over-interpret behavior yet.

---

### 4. Capability Discovery from Functions and Behavior

Now, **treat the codebase and the running tool like an unknown machine**. Your job is to infer “what it can do” from its observable parts.

For each significant entry point (command, API, route) and major module:

#### 4.1 Behavioral probing (if you can run it)

- Run **safe** commands / operations to see what happens:
  - `tool --help`, `tool <command> --help`, etc.
  - Dry-run, `--list`, `--analyze` on sample or small/dummy inputs (if available/supplied).
- Observe:
  - Types of inputs it accepts.
  - Types of outputs it produces.
  - Any obvious workflow implied by the sequence of allowed commands/flags.

#### 4.2 Static probing (from code) when you can’t run

- Read function and class names, signatures, and docstrings.
- Trace:
  - Data flows,
  - Main processing pipelines (ingest → parse → analyze → output),
  - Key algorithms or heuristics.

#### 4.3 Capability extraction checklist

For each major behavior you see (via runtime or code):

Ask yourself:

1. **What does this behavior *achieve* for a user or system?**  
   - Does it acquire or read data?  
   - Does it parse or normalize some format?  
   - Does it analyze, detect, or classify something?  
   - Does it aggregate, correlate, or build a timeline?  
   - Does it export, report, visualize, or notify?

2. **Is this a repeatable outcome that is meaningful by itself?**  
   - If yes, define it as a **capability**.  
   - If it’s just a small support function, treat it as part of a larger capability.

For each **discovered capability**, record:

- **[Observed Capability #N: Name]**  
  - What it is (identity):  
    - One-sentence description of what this capability *does* for a user/system.  
  - What it’s for (purpose):  
    - Which user/role or use case this capability likely serves.  
  - Inputs:  
    - Specific data types, file formats, parameters, or states it needs.  
  - Outputs/effects:  
    - Files, logs, reports, changed state, return values, or other observable effects.  
  - How to invoke it:  
    - Concrete CLI command(s), API calls, or function calls.  
  - Origin in code:  
    - Key files, classes, and functions that implement it.  
  - Observation type:  
    - Mark as `Observed by running`, `Inferred from code`, or `Both`.

Be generous but precise: include all user-meaningful capabilities you can infer, even if small (e.g., “exports results as JSON”).

---

### 5. “What It Claims vs What It Is” – Verification Against Docs/Help

If you found any claimed capabilities in Section 2, now compare them against the capabilities you **actually discovered** in Section 4.

For each claimed capability:

1. Try to match it with one or more observed capabilities by purpose.
2. Decide:

   - `match` – the claim aligns with reality.  
   - `partial` – some aspects match; others (inputs, outputs, behavior) do not.  
   - `mismatch` – actual behavior differs significantly from the claim.  
   - `not_found` – you could not find any implementation for what’s claimed.

3. Record:

- **[Capability: Name]**  
  - Claimed (from docs/help):  
    - Short paraphrase of what the docs say it is/does.  
  - Observed actual behavior:  
    - What you see in code and/or runtime.  
  - Status: `[match | partial | mismatch | not_found]`  
  - Notes:  
    - Specific differences, missing options, changed behavior, or risks.

If there were **no docs at all**, state clearly:

> “There was no documentation; all capabilities and tool identity are inferred from code structure and observed behavior only.”

---

### 6. Undocumented / Hidden Capabilities

Identify any capabilities that:

- You have **evidence for in code or behavior**, and  
- Are **not mentioned** in any visible documentation or help text.

For each:

- **[Undocumented Capability #N: Name]**  
  - What it is: concise description.  
  - How to invoke: precise CLI/API/library usage.  
  - Evidence: key code locations and/or example output.  
  - Why this matters:
    - Why it is important, useful, risky, or surprising that this capability exists without being documented.

---

### 7. Missing or Weak Capabilities (Relative to Its Inferred Purpose)

Now that you have a working picture of **what it is** and **what it can do**, step back and evaluate it as a product/tool for its inferred domain.

1. Restate, in light of your findings:
   - What this tool *actually appears to be for*.  
   - Which high-level problems or workflows it tries to solve.

2. Based on that inferred purpose and typical domain expectations, identify:

   - **Missing capabilities** that a reasonable user would expect this kind of tool to have, but which you did not find.  
   - **Weak/brittle capabilities** that exist but appear limited or fragile.

For each:

- **[Missing or Weak Capability]**  
  - Type: `[Missing | Weak]`  
  - Description: what is missing or underpowered.  
  - Domain rationale: why this would be expected in tools of this type.  
  - Evidence:
    - TODOs, partial implementations, obvious gaps in workflows, or complete absence.

---

### 8. Capability Quality, Risk, and Priority

For each **observed capability** from Section 4, assess how solid it appears to be.

- **Maturity** (pick one and justify):
  - `Prototype` – experimental, limited, or messy.  
  - `Works but fragile` – appears to work but with little validation, error handling, or resilience.  
  - `Stable / production-usable` – generally robust, with reasonable checks and structure.  
  - `Mature / well-engineered` – clean abstraction, good structure, clear extensibility.

- **Risks / weaknesses**:
  - Poor input validation, lack of error handling, brittle assumptions.  
  - Performance red flags (e.g., naive loops over large data, unbounded memory use).  
  - Security concerns (if parsing untrusted input or interacting with networks/systems).

- **Priority to improve** (High / Medium / Low):
  - High: core to the inferred purpose and clearly weak/fragile or opaque.  
  - Medium: useful but not core or moderately flawed.  
  - Low: niche or already fine.

Format:

- **[Capability Name] – Assessment**  
  - Maturity: … (because …)  
  - Risks / weaknesses: …  
  - Priority: … (because …)

---

### 9. Final Structured Outputs

Provide three consolidated views.

#### 9.1 “What This Tool Is” – Identity Summary

- A short description (2–5 sentences) of:
  - What this tool appears to be.  
  - Who it is for.  
  - The main problems or workflows it supports, based only on your code/behavior observations.

#### 9.2 Capabilities Catalog (Human-Readable)

A structured list of the **observed capabilities**:

For each:

- Name  
- Short description (what it does and for whom)  
- Inputs  
- Outputs/effects  
- Example usage (CLI/API/function)  
- Notes/limitations  
- Observation type (Observed by running / Inferred from code / Both)

#### 9.3 Capabilities Summary Table

A compact table:

| # | Capability Name | Observation Type (Run/Code/Both) | Status (OK/Partial/Broken) | Maturity | Priority | Docs Presence (None/Partial/Good) |
|---|-----------------|-----------------------------------|----------------------------|----------|----------|-----------------------------------|
|   |                 |                                   |                            |          |          |                                   |

#### 9.4 Key Findings & Next Steps

- **Top Strengths**  
  - [Capability] – why it is strong or valuable.

- **Top Unknowns / Uncertainties**  
  - [Area] – what you could not conclusively determine and why.

- **Top Documentation Gaps**  
  - [Capability/area] – what absolutely needs to be documented to make the tool understandable.

- **Top Improvement Opportunities**  
  - [Capability/area] – what to improve or add to better align with its inferred purpose.

- **Recommended Next Steps (prioritized, concrete)**  
  - 5–10 specific actions (e.g., “Document command X with examples,” “Add error handling to Y,” “Implement Z capability to complete workflow W”).

---

### Behavioral Rules

- **Think like an archaeologist and debugger combined.**  
  You are reverse-engineering what this tool *is* and *does*, from its traces.

- Never mark a capability as “confirmed” without clear code evidence or a successful run path.
- Always clearly label what is *observed*, *inferred*, or merely *claimed* by docs/comments.
- When docs and behavior conflict, **trust the code/behavior**, and flag the docs as incorrect/outdated.
- Prefer concrete examples (commands, function names, file paths) over vague descriptions.

Use this entire prompt as your instructions. After this prompt, I will provide you with the repository/code, instructions for running the tool (if possible), and any sample data. Then you should execute this Software Capabilities Audit and return your results in the structured formats specified above.
