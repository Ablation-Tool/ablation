# Contributing to Ablation

## Reporting issues

Before submitting a patch, check the [issue tracker](https://github.com/Ablation-Tool/ablation/issues):

- **Bug?** Open a bug report. Include your Python version, OS, the failing command, and the full traceback.
- **Feature request or idea?** Open a feature request, or reach out directly. Describe the RE task, not the implementation -- what analysis goal is currently impossible or painful. All suggestions are welcome.

You can also reach out directly for anything:

- Email: [ablation@nuclide-research.com](mailto:ablation@nuclide-research.com)
- X: [@ablation_tool](https://x.com/ablation_tool)
- Signal: [@deadbug.06](https://signal.me/#p/deadbug.06)

---

## Setup

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e ".[full]"
```

## Project layout

```
ablation/
  analyzers/          core analysis modules
    binary_context.py   ELF/PE/Mach-O parsing, string extraction, import resolution
    xref_graph.py       call graph + RIP-relative string xref (vectorized NumPy)
    cfg_builder.py      per-function CFG via iterative recursive disassembly (Capstone)
    corpus_builder.py   builds behavioral fingerprints into func_id.db
    semantic_search.py  BERT query engine over func_id.db
    pattern_library.py  pattern registry + sweep runner
    taint_tracker_x86.py  taint analysis from network sources to dangerous sinks
    finding_registry.py  confirmed findings store
  core/               low-level helpers (disasm, parsing)
  cli.py              installed entry point (ablation <subcommand>)

sweeps/               sweep scripts (extend base_sweep.py)
modules/              optional platform-specific modules
examples/             runnable demos
tests/                pytest test suite
```

## Adding a vulnerability pattern

Patterns live in `PatternLibrary` (`ablation/analyzers/pattern_library.py`). Each pattern is a plain-English description of a vulnerable function's behavior -- the same description you'd use to explain it to a peer.

```python
from ablation.analyzers.pattern_library import PatternLibrary, Pattern

pl = PatternLibrary()
pl.add(Pattern(
    query="function that parses a length field from the network and passes it unchecked to memcpy",
    tag="memory-safety",
))
```

Good patterns:
- Describe **behavior**, not implementation details (no register names, no specific library functions)
- Are specific enough to score above 0.30 on real targets but general enough to match across vendors
- Have a `tag` matching an existing category: `memory-safety`, `auth`, `crypto`, `info-leak`, `dos`

Run your pattern against a real binary to verify it fires:

```bash
ablation sweep /path/to/firmware.so --min-score 0.30
```

## Adding a sweep

Sweeps are scripts in `sweeps/` that extend `BaseSweep`:

```python
# sweeps/my_sweep.py
from sweeps.base_sweep import BaseSweep

class MySweep(BaseSweep):
    def patterns(self):
        return [
            "function parses length field without bounds check",
            "authentication bypass via error path return",
        ]
```

Run: `ablation-sweep --sweep my_sweep --binary /path/to/target`

## Adding an analyzer module

If you find a gap -- a binary type or analysis technique Ablation doesn't cover -- add it as a module:

1. Create `ablation/analyzers/my_module.py`
2. Add a `_cli()` function for standalone testing
3. Add a `[project.scripts]` entry in `pyproject.toml` if it warrants its own command
4. Add a test in `tests/test_my_module.py`

## Running tests

```bash
python -m pytest tests/ -x -q
```

The test suite does not require model downloads -- semantic search tests use a small mock corpus.

## Submitting changes

Open a pull request against `main`. The CI workflow runs import smoke tests and the core analyzer tests on every push.
