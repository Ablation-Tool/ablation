# undocumented_ppc_opcodes — POWER ISA simulator opcode gap scanner

## Why this exists

1. IBM ships functional simulators (sim_ppc, systemsim) with text `decode.map` files that list
   every opcode the hardware implements, including management-only instructions not documented
   in public IBM POWER ISA books.
2. Firmware analysis (FSP, hostboot, OPAL) sometimes uses these internal instructions. Knowing
   their encodings requires either the simulator maps or hardware documentation IBM has not published.
3. Cross-generational comparison (POWER7 → POWER9 → POWER10) reveals when undocumented
   instructions were added, changed, or removed — useful for security research.

## Constructor

```python
from ablation.analyzers.undocumented_ppc_opcodes import PPCOpcodeScanner

scanner = PPCOpcodeScanner(
    p7_map  = '/path/to/sim_p7/bin/decode.map',   # optional
    p8_map  = '/path/to/sim_p8/bin/decode.map',   # optional
    p9_map  = '/path/to/sim_p9/bin/decode.map',   # optional
    p10_map = None,   # no decode.map in systemsim-p10 1.2-4
)
```

Where to find decode.map files:

| Package | Path after extraction |
|:---|:---|
| `sim_ppc-power7-1.0-2626.x86_64.rpm` | `opt/ibm/sim_ppc/sim_p7/bin/decode.map` |
| `sim_ppc-power8-1.0-752.4.1.x86_64.rpm` | `opt/ibm/sim_ppc/sim_p8/bin/decode.map` |
| `sim_ppc-power9-1.0-2581.x86_64.rpm` | `opt/ibm/sim_ppc/sim_p9/bin/decode.map` |
| `systemsim-p10_1.2-4_amd64.deb` | No decode.map (table compiled into binary) |

## Key methods

```python
findings = scanner.scan()           # → list[OpcodeGapFinding]
print(scanner.report(findings))     # → str
```

## Finding kinds

| kind | Description |
|:---|:---|
| `primary0` | Instruction at primary opcode 0 (reserved/trap in public POWER ISA user space) |
| `internal_unit` | Instruction routed to CMU (Chip Management Unit) — management-only |
| `mnemonic_dash` | Reserved entry with no public mnemonic (`-`) |
| `added` | Present in newer generation, absent in older |
| `removed` | Present in older generation, absent in newer |

## Known confirmed findings (P7/P9)

| Mnemonic | Kind | Note |
|:---|:---|:---|
| `sp_attn` | primary0 | Special Attention interrupt — opcode 0, XO 0x100 (P7) / 0x200 (P9). Not in public POWER ISA user-space spec. Absent in POWER10. |
| `rvwinkle` | internal_unit | "Runlatch Winkle" — POWER7 only lab/test power mode. Removed in POWER9. |
| `doze` / `nap` / `sleep` | internal_unit | POWER7 power management modes. Unified into `stop` in POWER9. |

## Known false positives (CMU-routed public instructions)

The CMU filter over-fires on instructions that IBM routes through the Chip Management Unit
internally but ARE documented in the public POWER ISA:
- `sc` (System Call), `rfid`, `hrfid` — architectural instructions
- `isel` — Integer Select (added in POWER ISA 2.03)
- `dst`, `dstst`, `dss`, `dsstall` — AltiVec Data Stream Touch prefetch

These are in `PUBLIC_POWER_ISA_MNEMONICS` but the CMU check runs before the public-set filter.
Fix: add `and e.mnem not in PUBLIC_POWER_ISA_MNEMONICS` to the `internal_unit` branch.

## POWER10 (systemsim-p10 1.2-4)

No `decode.map` file. Opcode table is compiled into the `systemsim-p10` binary (stripped).
String evidence from binary: `sp_attn` absent (removed in P10), `stop` present (42 refs),
`darn`/`copy`/`paste`/`bctar` present, `pfx00_`/`pfx01_` prefixed-instruction decode visible.
