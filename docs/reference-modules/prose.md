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

---

## How it works

`check(text)` splits the input on newlines and applies a fixed set of compiled `re.Pattern` rules to each line: `em_dash` matches `\s—\s` or `—`; `parenthetical` matches `\([^)]{8,}\)` (parenthetical phrases over 8 characters); `filler` matches a list of banned phrases (e.g., `comprehensive`, `fully`, `simply`, `leverage`); `ai_copy` matches phrases common in AI-generated prose (e.g., `delve into`, `in the realm of`). Each match produces a `ProseIssue` with rule, line, column, matched text, and a suggestion string. `check_file(path)` reads the file and calls `check()`. `report(issues, filename)` formats them as a human-readable list. The CLI entry point exits with code 1 on any violation so it can gate pre-commit hooks.

---

## Example output

```
$ python3 -m ablation.core.prose docs/reference-modules/forge.md
forge.md:3:12  em_dash      "FORGE — the audit gate"
               → Use a period or "because" instead of an em dash.
forge.md:18:5  filler       "fully automates"
               → Drop "fully"; "automates" carries the meaning.
forge.md:41:9  parenthetical  "(parse, scan, detect)"
               → Inline the items or use a list.
3 violations found.
[exit code 1]
```

---

## False positives

**`parenthetical` false positive on code spans**: a parenthetical like `(e.g. SHA256)` or `(default 0.62)` exceeds 8 characters and will trigger the rule even though it is appropriate in technical docs. Inline code using backticks instead of parentheses to avoid the rule: `` default `0.62` `` instead of `(default 0.62)`.

**`filler` on legitimate compound words**: phrases like `simply put` and `leverages` are caught by the filler and ai_copy rules, but a domain-specific compound like `leverage ratio` in a finance context is not a filler phrase. Extend the rule set with a per-project allowlist if the default rules produce excessive noise.

---

## Pipeline position

**Before this module:** No prerequisites. `check(text)` and `check_file(path)` can be called standalone on any markdown string or file path.

**After this module:** Fix all reported violations before committing documentation or module docstrings. Wire `python3 -m ablation.core.prose` into a pre-commit hook to enforce the standard automatically.

---

## Reading output

`prose.check(text)` and `prose.check_file(path)` return `list[ProseIssue]`:

| Attribute | Content |
|:---|:---|
| `rule` | Rule that triggered: `'em_dash'` / `'parenthetical'` / `'filler'` / `'ai_copy'` |
| `line` | 1-indexed line number |
| `col` | 1-indexed column of the match |
| `text` | Matched text that violated the rule |
| `suggestion` | Replacement guidance |

---

## See also

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
