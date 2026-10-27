# SpiceAnalyzer

Extract transistor counts, supply rails, and topology classifications from SPICE netlists without running a simulation.

---

## Why this exists

1. **BCC is a custom TSMC 0.25µm IC with 11,434 transistors and a 600ms SPICE simulation deck.** Reading the SPICE file directly recovers the power supply voltages, the differential I/O pairs, and the bias network topology in under one second. Running the simulation takes hours and requires a licensed SPICE engine.

2. **LVDS terminator resistors directly name the BCC-to-ABCn signal pairs.** The test bench declares `R_DATAOUT DATAOUT_P DATAOUT_M 100`, `R_ABCN_BCO BCO_P BCO_M 100`, etc. Parsing only the resistor lines gives the complete differential I/O inventory: DATAOUT, ABCN_RESETB, ABCN_L1, ABCN_COM, ABCN_DCLK, ABCN_BCO.

3. **Current mirror identification maps the bias network.** The trimmed BCC netlist contains PMOS mirrors biased from VDD (PMOS load bias) and NMOS mirrors biased from GND (tail current sources for diff pairs). These are recoverable from the netlist graph without simulation.

4. **Supply rails from voltage source declarations confirm process and I/O technology.** BCC shows VDD=2.5V (TSMC 0.25µm core) with differential swing at 1.1V/1.3V (100mV LVDS swing, 1.2V common mode). Both values match the expected facility radiation-hard TSMC 0.25µm specification.

---

## Constructor

```python
from ablation.analyzers.spice_analyzer import SpiceAnalyzer

sa = SpiceAnalyzer.from_path('/path/to/bcc_spice_test_1.cir')
print(sa.topology_summary())
```

Parses a flat SPICE netlist (`.cir` or `.sp`). Handles SPICE continuation lines (lines starting with `+`). Does not expand `.include` or `.subckt` definitions.

---

## Key methods

| Method | Returns |
|---|---|
| `sa.topology_summary()` | Transistor counts, supply rails, topology class, structure list |
| `sa.classify()` | Dominant topology: `lvds`, `diff_pair`, `current_mirror`, `cmos_logic`, `pmos_pad_array`, `unknown` |
| `sa.transistor_count()` | Total MOSFET instances |
| `sa.transistors_by_type()` | Dict: `{'pmos': N, 'nmos': M}` |
| `sa.supply_rails()` | List of unique positive supply voltages found in DC voltage sources |
| `sa.known_structures()` | List of StructureHit (type, devices, nodes, description) |

---

## Example: BCC trimmed netlist

```python
sa = SpiceAnalyzer.from_path('/path/to/at_bccsimnew_1_trimmed_again.cir')
print(sa.transistors_by_type())  # {'pmos': 6638, 'nmos': 4796}
print(sa.supply_rails())         # [1.1, 1.3, 2.5]
print(sa.classify())             # 'lvds'
for s in sa.known_structures()[:4]:
    print(s.description)
# pmos current mirror: ref=M33 mirrors=['M1', 'M2', 'M3']
# nmos current mirror: ref=M289 mirrors=['M257', 'M258', 'M259']
# LVDS termination 100Ω between DATAOUT_P/DATAOUT_M
# ...
```

---

## Topology signatures

| Signature | Classifier |
|---|---|
| PMOS with gate == drain (diode-connected), another PMOS with gate at that node | `current_mirror` |
| Two same-type FETs with shared source, different gates, different drains | `diff_pair` |
| Resistor with value 80–120Ω between two nodes | `lvds` |
| PMOS and NMOS with the same gate and same drain node | `inverter` |

---

## Limitations

- `.include` and `.subckt`/`.ends` definitions are not expanded. A test bench that `.include`s the cell library will show 0 transistors.
- BJT (`Q`), JFET, capacitor (`C`), inductor (`L`) instances are silently skipped.
- Subcircuit hierarchy is not resolved. Only flat top-level instances are classified.
- PWL/PULSE voltage sources are not parsed as supply rails — only DC sources with a bare numeric value.

---

## FORGE status

**PASSED** 0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW. Cached in ~/.ablation/forge_cache.json.
