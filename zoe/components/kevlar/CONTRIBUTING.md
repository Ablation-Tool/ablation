# Contributing

## Adding indicator patterns

Patterns live in two registries in `policy.py`:

- `_RAW_DESCRIPTION_PATTERNS` — scanned against tool/resource/prompt **descriptions** (prose fields that are always stripped by CDR). Be aggressive; false positives here cost only a log entry.
- `_RAW_CONTENT_PATTERNS` — scanned against **tool call responses** (content that reaches the LLM). Be conservative; every false positive quarantines real data.

Each entry:

```python
{"id": "INDICATOR_ID",  # stable kebab-case string, used in SIEM logs
 "severity": "high",    # high | medium | low
 "regex": r"...",       # compiled with re.IGNORECASE
 "mask": False},        # True = redact the matched value in log snippets
```

**Before adding a pattern:**
1. Check it against the false-positive corpus in `TestNewPatterns.test_clean_description_no_new_false_positives` — legitimate tool descriptions must not fire.
2. Add a test in the appropriate `TestNew*` class that fires on the target payload.
3. Add a test that confirms the benign equivalent does not fire.

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

All 149 tests must pass. The `tests/hostile_server.py` stub covers protocol-level and CDR integration paths; `tests/test_policy.py` covers the pure policy engine.

## Code style

- `policy.py` is pure Python, no I/O, no dependencies. Keep it that way.
- `kevlar.py` is the async proxy. Blocking calls in async functions are acceptable on the stdio I/O boundary (stdout write, audit log flush) but should be avoided elsewhere.
- No comments explaining what the code does. Comments explain non-obvious constraints, invariants, or security rationale.
