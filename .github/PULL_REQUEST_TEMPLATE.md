## What this changes

<!-- One paragraph. What problem does this solve or what capability does it add? -->

## How to test it

<!-- The exact commands or Python snippet to verify the change works. -->

```bash

```

## Tested on

<!-- Name the binary or firmware you ran this against. "ls" is fine for parser fixes; a real firmware image is expected for new analyzers. -->

- Binary:
- Architecture:
- Stripped:

## Checklist

- [ ] `python -m pytest tests/ -x -q` passes
- [ ] `ablation --help` still works
- [ ] No new imports added outside `pyproject.toml` dependencies
- [ ] If this adds a new analyzer: `from_context(ctx)` classmethod, `scan()` or `query()` method, `report()` method
