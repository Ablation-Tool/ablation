# VerilogSemantic

Extract protocol constants, FSM state encodings, and signal names from Verilog and VHDL source trees without a full grammar parser.

---

## Why this exists

1. **ATLAS hardware firmware source files are in Verilog and VHDL, not ELFs.** ABCN ASIC RTL (33 Verilog files), BCC (5 VHDL files), HSIO, and TIM firmware all need constant extraction before any protocol RE can begin. SemanticSearcher requires a BinaryContext. VerilogSemantic works directly on the source.

2. **Protocol constants are in VHDL `constant` and Verilog `parameter` declarations.** BCC's BROADCASTID ("111111"), CONFIG_RESET_VALUE ("0000011100000001"), LEADER_LEN (3), and ADDRESS_LEN (6) are all declared as VHDL constants. Extracting them by regex takes seconds and produces a dict ready to encode in an RE module.

3. **FSM state names are not preserved in bitfiles.** A VHDL `type states is (s_WaitStart, s_Leader, ...)` declaration gives the full state machine in one line. BCC has 12 states. Without this tool you reconstruct them from binary trace, which takes hours.

4. **query() accepts the same keyword interface as SemanticSearcher** so the RE workflow stays consistent when the target is HDL source instead of a binary.

---

## Constructor

```python
from ablation.analyzers.verilog_semantic import VerilogSemantic

vs = VerilogSemantic.from_directory('/path/to/rtl/')
print(vs.summary())
```

Parses all `.v`, `.vhd`, and `.vhdl` files under the directory. Silently skips unreadable files.

---

## Key methods

| Method | Returns |
|---|---|
| `vs.summary()` | Module/entity count, constant count, FSM state count, total lines |
| `vs.query('keyword1 keyword2')` | List of QueryHit (file, line, module, signal, context) |
| `vs.constants()` | Dict: name -> {'value', 'file', 'line'} |
| `vs.state_encodings()` | Dict: state_name -> {'encoding', 'source', 'file', 'line'} |
| `vs.modules()` | List of module and entity names |
| `vs.port_widths()` | Dict: signal_name -> bit width as integer |

---

## Example: BCC VHDL

```python
vs = VerilogSemantic.from_directory('/path/to/bcc/vhdl_0.2/')
c = vs.constants()
print(c['BROADCASTID']['value'])        # '"111111"'
print(c['CONFIG_RESET_VALUE']['value']) # '"0000011100000001"'
print(c['LEADER_LEN']['value'])         # '3'

for name, enc in vs.state_encodings().items():
    print(name, enc['encoding'])
# s_WaitStart 0
# s_Leader    1
# s_Address   2
# s_ComDest   3
# ...
```

---

## Coverage

| Language | Elements extracted |
|---|---|
| Verilog | module, parameter, `define, assign constants, port widths |
| VHDL | entity, constant, signal width, type enum (FSM states) |

SystemVerilog and VHDL-2008 syntax not supported. Block comments (/* ... */) are not stripped before extraction so commented-out parameters may appear in constants().

---

## FORGE status

**PASSED** 0 CRITICAL, 0 HIGH, 1 MEDIUM, 2 LOW. Cached in ~/.ablation/forge_cache.json.

| Finding | Severity |
|---|---|
| O(N*M) line offset scan in _lineno() because each match does a sorted dict scan | MEDIUM |
| Block comments not filtered before parameter extraction | LOW |
| Duplicate constant keys overwrite silently | LOW |
