# HDLVersionDiff

Compare two versions of an HDL source tree and report what changed at the constant, signal, port, and FSM level.

---

## Why this exists

1. **VerilogSemantic scans one directory. It has no memory of any other version.** When a component ships 8 VHDL generations (BCC v0.2–v0.9), `VerilogSemantic` can tell you what is in each one but cannot tell you what changed between them. The only prior workflow was: extract two archives, run `VerilogSemantic` on each, write down the results, compare manually. For 8 versions that is 28 pairwise comparisons.

2. **VHDL constant values encode design decisions that are invisible at the bit level.** When BCC added `constdata_mode` and `abcn_bco2x_en` in v0.9, the reason — a protocol timing change driven by ABCn end-mode token behavior — is encoded in the signal declaration and its surrounding comments. A bitstream-level diff cannot surface this. A constant-level diff between v0.8 and v0.9 makes it the first result.

3. **Version skips and numbering gaps are only visible as a timeline.** BCC has a v0.6 and a v0.8 but no v0.7. Whether v0.7 was silently replaced or never archived changes the interpretation of what v0.8 fixed. A sweep across all archived versions answers this by showing which pairwise diffs are large (structural change) vs. small (patch).

4. **Signal width changes are protocol changes.** When a counter widens from 4 bits to 8 bits between versions, or a bus narrows, or a state enum gains or loses states, the design intent changed. `VerilogSemantic.port_widths()` returns widths for one version. There is no tool that says "this signal was 4 bits in v0.4 and is 8 bits in v0.6."

---

## How it works

`HDLVersionDiff` runs `VerilogSemantic` on two directories (old, new) and computes set and value differences across four dicts: `constants()`, `port_widths()`, `state_encodings()`, and `modules()`. It returns a structured diff object with per-category change lists.

```
directory_old/ ──► VerilogSemantic ──► snapshot_old ──┐
                                                       ├──► HDLVersionDiff ──► DiffReport
directory_new/ ──► VerilogSemantic ──► snapshot_new ──┘
```

Constants that exist in both versions are compared by value string. A change is recorded if the stripped value differs. Port widths are compared numerically. FSM states are compared by name; a state that moves from index 3 to index 7 is reported as changed, not as remove+add.

The diff object does not interpret changes — it reports them. Interpreting a constant rename as a refactor vs. a semantic change is left to the RE module author.

---

## HDLVersionDiff

```python
from ablation.analyzers.hdl_version_diff import HDLVersionDiff

diff = HDLVersionDiff.from_directories('/path/to/bcc_vhdl_0.8/', '/path/to/bcc_vhdl_0.9/')
print(diff.report())
```

`from_directories(old_dir, new_dir)` runs `VerilogSemantic.from_directory()` on each path and builds the diff. Both directories must contain at least one `.v`, `.vhd`, or `.vhdl` file or the constructor raises `ValueError`.

---

## Key methods

| Method | Returns |
|---|---|
| `diff.added_constants()` | Dict of constants present in new but not old: name → new entry |
| `diff.removed_constants()` | Dict of constants present in old but not new: name → old entry |
| `diff.changed_constants()` | Dict of constants present in both with different values: name → {'old', 'new', 'file_old', 'file_new'} |
| `diff.added_signals()` | Dict of signals/ports added in new: name → width |
| `diff.removed_signals()` | Dict of signals/ports removed in new: name → width |
| `diff.changed_signals()` | Dict of signals whose bit-width changed: name → {'old_width', 'new_width'} |
| `diff.added_states()` | Dict of FSM state names added in new: name → encoding |
| `diff.removed_states()` | Dict of FSM state names removed in new: name → encoding |
| `diff.added_modules()` | List of entity/module names added in new |
| `diff.removed_modules()` | List of entity/module names removed in new |
| `diff.summary()` | One-line string: counts of each change category |
| `diff.report()` | Full formatted diff, grouped by category |

---

## Usage

```python
from ablation.analyzers.hdl_version_diff import HDLVersionDiff
import glob, os

# Single pairwise diff
diff = HDLVersionDiff.from_directories('bcc_vhdl_0.8/', 'bcc_vhdl_0.9/')
for name, chg in diff.changed_constants().items():
    print(f"  {name}: {chg['old']!r} → {chg['new']!r}")
for name, entry in diff.added_constants().items():
    print(f"  + {name} = {entry['value']!r}  ({entry['file']}:{entry['line']})")

# Sweep all consecutive version pairs
dirs = sorted(glob.glob('/media/cowboy/research/facility/asic/bcc/extracted/bcc_vhdl_0.*/'))
for old_dir, new_dir in zip(dirs, dirs[1:]):
    diff = HDLVersionDiff.from_directories(old_dir, new_dir)
    label = f"{os.path.basename(old_dir.rstrip('/'))} → {os.path.basename(new_dir.rstrip('/'))}"
    print(f"\n{label}")
    print(diff.summary())
    for name, entry in diff.added_constants().items():
        print(f"  + {name} = {entry['value']!r}")
    for name, chg in diff.changed_constants().items():
        print(f"  ~ {name}: {chg['old']!r} → {chg['new']!r}")
```

---

## Example output

```
bcc_vhdl_0.8 → bcc_vhdl_0.9
  2 added constants, 0 removed, 1 changed, 2 added signals, 0 removed, 0 changed

  + constdata_mode = '"1"'    (bcc_digital_top.vhd:47)
  + abcn_bco2x_en  = '"0"'   (bcc_digital_top.vhd:51)
  ~ TRAILER_COUNT: '"00001110"' → '"00010000"'  (trailer 14 BC → 16 BC)
```

The `TRAILER_COUNT` change from 14 to 16 BC, combined with the addition of `abcn_bco2x_en`, points to a timing margin change: the BCC was extended to tolerate ABCn token ring latency at 80 MHz readout. This is not visible in the bitfile; it is only visible in the constant diff.

---

## False positives

**Whitespace-only value changes.** VHDL constant values sometimes have inconsistent spacing (`"00001110"` vs `" 00001110"`). `changed_constants()` strips surrounding whitespace before comparing. Leading/trailing spaces inside string literals are not stripped — `'"1 "'` and `'"1"'` are reported as different. Verify by eye before treating as a semantic change.

**Renamed files with identical content.** If a VHDL entity was split across two files in one version and merged into one file in the next, all constants from the split file appear as removed and re-added. Check `file_old` and `file_new` fields — if they differ but values match, it is a file reorganisation, not a design change.

**Parameter-generic interactions.** VHDL generics with defaults appear in `constants()`. If a module's generic default changes from 4 to 8, it is reported as a constant change even if the instantiation always overrides it. Check whether the changed constant is a `generic` or a true `constant` before treating it as a protocol change.

---

## Pipeline position

**Before this module:** `VerilogSemantic.from_directory()` on each version to verify both parse cleanly. If `summary()` shows 0 constants on either side, the regex extractors have not matched the dialect — check the file encoding.

**After this module:** Encode changed constants directly into the RE module. A `changed_constants()` result maps 1:1 to a new or updated value in `bcc_re.py`, `abcn_re.py`, etc. Use `added_states()` to prime an `OneHotFSMExtractor` query — new FSM states often accompany new features.

---

## See also

- [VerilogSemantic](verilog-semantic.md): the single-version scanner this module extends
- [OneHotFSMExtractor](one-hot-fsm-extractor.md): extracts state transition tables from Verilog one-hot combinational assigns; use when `added_states()` shows new states you want to understand
