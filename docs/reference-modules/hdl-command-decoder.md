# HDLCommandDecoder

Extract bus-visible command decoders from VHDL and Verilog sources: the command table, each command's signal-level effects, and whether the dispatch is guarded by anything beyond a bare strobe.

---

## Why this exists

1. **Command decoders are the highest-value RTL target class.** The ALICE Pixel Trigger review (control, OPTIN, processing FPGAs) found the same pattern three times: a constant-declared command table, a `case` on the command signal, and a single strobe gating dispatch with no authorization. Reading three decoders by hand took a full session. The extraction is mechanical and should be a tool.

2. **The effects matter as much as the encodings.** Knowing that `FF000000` is `COMMAND_RESET_PARAMETERS` is half the answer. The other half is that the arm drives `reset_parameters_n` low, and that a settings-bank process restores every `DEFAULT_*` register when it does. Per-arm effect extraction (`signal <= value`, with simulation `after DELAY` stripped) captures that directly from the source.

3. **Guard shape is the security question.** A dispatch inside `if (command_en = '1')` is reachable by any bus writer. A dispatch inside `if (command_en = '1' and mode_unlocked = '1')` has a functional gate that must be reviewed separately. The tool classifies guards instead of leaving that judgment implicit.

4. **Version sweeps multiply the value.** The ALICE decoders are byte-identical across three firmware stages; establishing that by hand meant extracting nine archives. Combined with `HDLVersionDiff`, decoder tables can be compared across releases directly.

---

## How it works

Regex/structural sweep, not an AST or elaboration. For each `case` statement it:

1. Resolves `when CONSTANT =>` arms through the file's constant declarations (`X"..."`/`B"..."` VHDL literals, `localparam`/`parameter` Verilog values). Literal arms (`when X"8000001F"`) are used directly. `when others` / `default` arms are skipped.
2. Records per-arm signal assignments as effects, stripping `after <delay>` clauses and ignoring `assert`/`report` statements.
3. Computes the *enclosing* if-conditions with an if/end-if nesting scan. Sibling statements before the case (e.g. an unrelated automatic-reset `if`) are not guards; this was a real false-positive in the ALICE control decoder.
4. Marks the dispatch **unguarded** when every non-reset guard references only strobe/enable/clock signals (`*_en`, `*_strobe`, `write_en`, ...). Any other signal in a guard (mode, unlock, state) marks it guarded. FSM-like selectors (`*state*`) get an advisory note, and auth-related terms anywhere in the file get a manual-review note.

```
constants ──┐
case arms ──┼──► per-command table {name, value, effects[]} ──► DecoderReport
if nesting ─┘        + guards + unguarded flag                      (+ notes)
```

---

## Usage

```python
from ablation.analyzers.hdl_command_decoder import HDLCommandDecoder

dec = HDLCommandDecoder.from_directory('analysis/alice-optin/')
print(dec.summary())
# optin_command_decoder.vhd:114 case optin_command unguarded=True ...
#   0xFF000000 COMMAND_RESET_PARAMETERS: int_reset_parameters_n <= '0'
#   ...

data = dec.to_dict()   # JSON-serializable command tables + verdicts
```

Validated against the three ALICE decoders: OPTIN (28 commands across two case statements), processing (3), control (19, 8-bit codes). All match the manually reviewed tables, including the unguarded verdicts.

## Limits

- Nested `case` statements, `generate` loops, and dispatch through subprograms are not followed.
- Guard classification is syntactic. A `mode_unlocked` signal might itself be trivially settable; "guarded" means *review the guard*, not *safe*. "Unguarded" is an RTL-level statement, not proof of bus or network reachability.
- Verilog support covers the common `case (command)` idiom; `casex`/`casez` wildcard semantics are not evaluated.

## Reproduce

`tests/test_hdl_command_decoder.py` (8 tests) mirrors the three ALICE decoder shapes, including the sibling-if regression and the guarded/unguarded split for both languages.
