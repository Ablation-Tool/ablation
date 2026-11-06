# HDLWritePath

Trace a VHDL signal — typically a command register or its strobe — backwards through the design to the primary input ports that drive it, carrying every enclosing condition along the way.

---

## Why this exists

1. **The decoder verdict is only half the reachability question.** `HDLCommandDecoder` establishes that a `case` dispatch has no authorization. The remaining question — which bus inputs can actually produce that dispatch, and under which address decode and state-machine conditions — required hours of manual grep-and-read per design. In the ALICE OPTIN review that chain had nine hops across three files; this module recovers it in seconds.

2. **Strobes are driven by conditions, not expressions.** A command strobe is usually `reg_optin_command_en <= '1'` under `write_en='1' and address=CONST`. Tracing only assignment expressions dead-ends at the literal. The tracer also follows *condition references*, which is where the real write path lives.

3. **Address maps fall out for free.** Because address-decode comparisons reference `ADDR_*` constants, every trace resolves the implicated register addresses through the constant declarations. A single OPTIN strobe trace recovered all 100+ register addresses in the bank.

4. **Cross-entity tracing is where manual review breaks down.** `write_en` in the register file is `optin_registers_write` in the top level is `registers_write_en_i` in the bus target. Port-map edges (with direction checks) follow those renames mechanically, and a decoder's *input* port is never mistaken for a driver.

---

## How it works

1. **Parse** entities (balanced-parenthesis port lists — naive regexes truncate at the first `std_logic_vector(...)`), architectures, aliases, constants, concurrent assignments (`when/else` included), process-body sequential assignments (labeled `end process NAME;` accepted), and instantiations with named port maps.
2. **Condition tracking**: a frame stack per process records the exact if/case branch of each assignment. `elsif`/`else` rewrite the innermost if-frame (`else` yields `not (...)`), each `when` rewrites the innermost case-frame, so sibling arms never leak conditions into each other. `after DELAY` clauses are stripped from expressions.
3. **Graph**: each assignment yields hops from the target to expression references *and* to condition references. Port maps yield direction-aware hops: a formal `in` port continues to the parent actual; an actual tied to a child `out` port continues into the child. Unknown child entities (primitives, black boxes) are skipped.
4. **Search**: breadth-first, each `(entity, signal)` expanded once — bounded even on large bus-target logic cones. One shortest driver chain per endpoint, plus the union of conditions and resolved `ADDR_*` constants. Depth, path-count, and expansion caps are reported as notes, never silently.

```
registers.optin_command_en
  → reg_optin_command_en            [assignment]
  → reg_block0_write_en             [condition: reg_address = ADDR_OPTIN_COMMAND]
  → int_block0_write_en             [assignment]
  → write_en                        [assignment]
  → top.optin_registers_write       [portmap]
  → bus_target.registers_write_en_i [assignment]
  → ... state machine / address_in ...
  → top.address                     [primary input]
```

---

## Usage

```python
from ablation.analyzers.hdl_write_path import HDLWritePath

tracer = HDLWritePath.from_directory('analysis/alice-optin/optin_fpga_firmware_stage090624')
report = tracer.trace('optin_registers.optin_command_en')
print(report.summary())          # paths, primary inputs, conditions, address map
data = report.to_dict()          # JSON-serializable

# Or drive it from a HDLCommandDecoder result:
reports = tracer.trace_decoder('optin_command_decoder',
                               selector='optin_command', strobe='optin_command_en')
```

Unscoped targets (`trace('reg_optin_command_en')`) resolve when exactly one entity declares the signal. Validated on the real ALICE OPTIN and processing designs: both command strobes trace end to end to the top-level bus `address` input, matching the manual reviews, including the bus-target write-state conditions (`state = s_bwr_data_phase`, `c_be_i = WRITE_BLOCK_COMM`).

## Limits

- VHDL only. Verilog sources are ignored (use `HDLCommandDecoder` for Verilog dispatch).
- Structural, not timed: conditions are textual, no simulation or satisfiability check. A reachable input port is not proof of external (e.g. network) reachability.
- Positional port maps, subprogram calls, generate loops, and record types are not followed; undriven endpoints and black-box instances are reported, not guessed.
- Paths are shortest chains per endpoint, not an exhaustive enumeration of every sensitization.

## Reproduce

`tests/test_hdl_write_path.py` (11 tests) mirrors the ALICE register-file structure: full port parsing, strobe/command chains across entities, case-arm isolation, else inversion, when/else concurrent assignments, alias hops, direction-correct port maps, and serialization.
