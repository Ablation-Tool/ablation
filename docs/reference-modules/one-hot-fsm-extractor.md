# OneHotFSMExtractor

Extract state transition tables from Verilog one-hot FSMs encoded as combinational `assign` statements.

---

## Why this exists

1. **`VerilogSemantic.state_encodings()` finds state names but not transitions.** It matches ALL-CAPS `parameter` declarations (e.g. `parameter ST_IDLE = 11'b00000000001`) to identify one-hot state names. The ABCn ROL and ROC FSMs have these parameters — but they are commented out. The active encoding is in the `statemachine` register and the `d_statem` combinational assigns. `state_encodings()` returns nothing. The transition table has to be read manually.

2. **One-hot combinational assigns are the standard ATLAS ASIC FSM encoding.** The pattern appears in every ABCn-family Verilog file that contains a state machine:
   ```verilog
   assign d_statem[N] = rst_b &
       (statemachine[A] & condition_1 |
        statemachine[B] & condition_2 & ~condition_3);
   ```
   `d_statem[N]` is the next-state value for state N. Each assign is a disjunction of (current_state & guard) terms. The full transition table is the set of all 11 (or N) such assigns. This is the same pattern in `rol_cntrl_hdl.v` (ROL), `roc_cntrl_hdl.v` (ROC), and any other ASIC RTL with a synthesis-friendly one-hot machine.

3. **Manual decoding is error-prone at the guard level.** The ROL FSM has guard conditions like `~send_id & ~send_reg & ~error_dcl & ~overflow & ~data_valid_dcl & ~end_hit`. Misreading one negation inverts a transition condition. A parser that extracts the expression tree and converts it to Python conditions will not make that mistake.

4. **Output signals are interleaved with state assigns in the same file.** `er[N] = statemachine[K]` wires the error code to a specific state. `nextout = statemachine[2] | statemachine[6] | ...` defines the `next_hit` pulse. These assigns are easy to miss when reading the file linearly. A dedicated extractor captures them in the same pass as the transition table.

---

## How it works

The extractor scans a Verilog file for two assign patterns:

**Next-state assigns:** `assign d_<name>[N] = <expr>;` — multi-line, terminated by `;`. The expression is parsed into a list of (source_state, guard_condition) pairs by matching `statemachine[M] & ...` terms in the disjunction.

**Output assigns:** `assign <signal>[N] = statemachine[K];` or `assign <signal> = statemachine[K] | statemachine[L] | ...` — maps output signal bits to one or more active states.

```
Verilog file
    │
    ├── next-state assign regex ──► (state_index, expr) pairs
    │       │
    │       └── expression parser ──► [(source_state, guard_str), ...]
    │
    └── output assign regex ──► (signal_name, active_states) pairs
            │
            └──► OneHotFSM.output_signals dict
```

Guard strings are returned as Python-readable boolean expressions with `~` replaced by `not ` and `&`/`|` replaced by `and`/`or`. No evaluation is performed — the strings are documentation, not executable code.

---

## OneHotFSMExtractor

```python
from ablation.analyzers.one_hot_fsm_extractor import OneHotFSMExtractor

fsm = OneHotFSMExtractor.from_file('/path/to/rol_cntrl_hdl.v')
print(fsm.report())
```

`from_file(path)` reads one Verilog file and returns an extractor instance. `from_directory(dir_path, next_state_pattern='d_statem')` scans all `.v` files for the pattern and returns a list of extractors, one per file that matched.

The `next_state_pattern` parameter is the prefix of the next-state register name. Default `'d_statem'` matches `d_statem[N]`. For `d_next[N]`, pass `next_state_pattern='d_next'`. For `d_state_ns[N]`, pass `'d_state_ns'`.

---

## Key methods

| Method | Returns |
|---|---|
| `fsm.states()` | List of state indices found (e.g. `[0, 1, 2, ..., 10]`) |
| `fsm.transitions()` | Dict: state_index → list of `(source_index, guard_str)` tuples |
| `fsm.output_signals()` | Dict: signal_name → list of state indices where it is active |
| `fsm.state_names()` | Dict: state_index → name string, from commented-out parameters or heuristic |
| `fsm.report()` | Full formatted transition table, one state per section |
| `fsm.as_python_dict()` | Python dict literal string, ready to paste into an RE module |

`state_names()` attempts to match state indices to names from three sources in priority order: uncommented `parameter ST_<name>` declarations, commented-out `\`define ST<N>` blocks, then falls back to `"ST{N}"`.

---

## Usage

```python
from ablation.analyzers.one_hot_fsm_extractor import OneHotFSMExtractor

fsm = OneHotFSMExtractor.from_file('/tmp/abcn_rtl/rtl_final/rol_cntrl_hdl.v')

# Transition table
for state_idx, edges in fsm.transitions().items():
    name = fsm.state_names().get(state_idx, f'ST{state_idx}')
    print(f"\n{name} ({state_idx:011b}):")
    for src, guard in edges:
        src_name = fsm.state_names().get(src, f'ST{src}')
        print(f"  from {src_name}  if  {guard}")

# Output signals
for sig, states in fsm.output_signals().items():
    state_names = [fsm.state_names().get(s, f'ST{s}') for s in states]
    print(f"{sig}: active in {', '.join(state_names)}")

# Paste-ready dict for the RE module
print(fsm.as_python_dict())
```

---

## Example output

For `rol_cntrl_hdl.v` with `next_state_pattern='d_statem'`:

```
ST9 (01000000000):
  from ST2   if  rst_b
  from ST3   if  rst_b
  from ST4   if  rst_b
  from ST5   if  rst_b
  from ST6   if  rst_b and end_hit
  from ST7   if  rst_b and end_hit
  from ST8   if  rst_b
  from ST9   if  rst_b and not time_up
  from ST10  if  rst_b

Output signals:
  token_out:  active in ST9
  nextout:    active in ST2, ST4, ST6, ST7, ST8, ST10
  er[2]:      active in ST3
  er[1]:      active in ST4
  er[0]:      active in ST5
```

The `as_python_dict()` output is formatted to paste directly into the RE module as `ROL_FSM_TRANSITIONS`.

---

## False positives

**Multi-module files.** If a Verilog file contains more than one module, assigns from different modules may be merged into one FSM. Use `from_file()` with single-module files, or check `fsm.states()` — a count above 20 with no clear one-hot pattern usually indicates a merge.

**Non-FSM one-hot assigns.** Some designs use one-hot encoding for priority arbiters or mux selects, not FSMs. These produce transition tables where every state transitions to every other state unconditionally. If `transitions()` shows N²-scale edges with no guard conditions, the target is not a state machine.

**Guard expressions with multi-bit comparisons.** The extractor handles single-bit signal references and `~` negations. Assigns of the form `statemachine[A] & (counter == 4'd15)` capture the comparison as an opaque string. The transition is extracted correctly but the guard renders as `counter == 4'd15` rather than a decomposed condition. Verify these manually.

---

## Pipeline position

**Before this module:** `VerilogSemantic.query('statemachine assign')` to confirm the target file uses the one-hot assign pattern. If `state_encodings()` already returns results, the file uses explicit `parameter` state names — use `state_encodings()` directly and skip this extractor.

**After this module:** `fsm.as_python_dict()` output goes into the RE module (`re/atlas/abcn_re.py`, etc.) as a `_FSM_TRANSITIONS` constant. Run `HDLVersionDiff` on consecutive versions to check whether any transitions changed between releases.

---

## See also

- [VerilogSemantic](verilog-semantic.md): single-version constant and signal extraction; run first to verify the file parses
- [HDLVersionDiff](hdl-version-diff.md): track how FSM transitions change across versions; `added_states()` output feeds directly into this extractor
