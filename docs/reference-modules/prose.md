# prose

`ablation/core/prose.py` checks documentation and README text for white-bronco violations before they ship. It catches em dashes, parenthetical feature lists, filler words, and AI copy patterns. Run it on any markdown file or string before committing docs.

---

## Why this exists

Three things were not possible before this module:

1. **Violations only surfaced after the user read the output and flagged them manually.** There was no automated check, so the same mistakes shipped more than once before anyone caught them.

2. **The style rules lived only in Claude's memory.** Other Claude sessions, other contributors, and other tools had no access to them. The style was not transferable.

3. **FORGE audited code correctness but had no prose gate.** A module docstring or README entry could ship with filler words and parenthetical lists without any signal from the gate.

---

## What it catches

| Rule | Example | Suggestion |
|------|---------|------------|
| `em_dash` | `FORGE: the audit gate` | Use a period or "because" |
| `parenthetical` | `(parse, scan, detect)` | Inline the items or use a list |
| `filler` | ``, ``, `` | Drop it |
| `ai_copy` | `delve into`, `in the realm of` | Say what it does |

---

## Usage

```python
from ablation.core.prose import check, check_file, report

issues = check("FORGE is a comprehensive tool that fully automates audits.")
print(report(issues))

issues = check_file('README.md')
print(report(issues, 'README.md'))
```

CLI:

```
python3 -m ablation.core.prose README.md
python3 -m ablation.core.prose docs/reference-modules/forge.md
cat commit_message.txt | python3 -m ablation.core.prose -
```

Exits with code 1 if violations are found, 0 if clean. Wire it into a pre-commit hook to block bad prose before it reaches the repo.

---

## White-bronco rules

The rules come from writing that passed without feedback and writing that was flagged.

The pattern that works: subject + verb + object. One sentence per idea. "because" for causation. "so" for consequence. One concrete number when possible.

The pattern that does not work: em dashes where a period would do. Parenthetical lists that bury the point. Filler words that describe nothing. Sentences that read like they were generated.
