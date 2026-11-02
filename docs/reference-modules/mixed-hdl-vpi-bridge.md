# Mixed VHDL/SystemVerilog VPI Bridge

`analysis/mixed-hdl/` contains a real two-way VHDL/SystemVerilog co-simulation bridge, a local GHDL/Icarus toolchain, and a reproducible integration runner. It exchanges scalar signals between independent simulator processes through the Verilog Procedural Interface (VPI).

## Why this exists

The Endeavour core is Verilog while its OCB host testbench is VHDL. Icarus alone cannot execute that composition, and translating the host would change the evidence being tested. A mixed-language bridge lets each simulator run its native source instead of substituting a rewritten model.

Two additional benefits are:

1. **Reusable external-tool validation.** The same C source builds against two VPI implementations with `-Werror`, exposing lifecycle, time-unit, and callback-scheduling differences in a small test before a large host is attempted.
2. **Deterministic integration evidence.** Both HDL sides assert their own expected values, and a separate missing-peer run proves that failure is bounded and visible rather than silent.

## Files

| File | Purpose |
|---|---|
| `ablation_vpi_bridge.c` | Bounded VPI callbacks, atomic value exchange, peer input driving, timeouts, and completion handling |
| `vhdl_side.vhd` | GHDL oscillator, source assertions, and delayed inverted-reply assertions |
| `verilog_side.sv` | Icarus heartbeat, source assertions, and inverted reply generation |
| `run_mixed_bridge.py` | Provisioning, strict builds, concurrent execution, negative test, and JSON evidence |
| `mixed-bridge-findings.json` | Generated result and limitation record |
| `evidence/` | Preserved VPI libraries and simulator logs |

The pinned local packages are under `analysis/tools/ghdl-5.0.1/` and `analysis/tools/iverilog-12.0/`; no root installation is required.

## Exchange protocol

Each side has one local output and one local input. At each synchronized timestamp it:

1. Reads its local output with `vpiIntVal` and rejects X, Z, malformed, or multi-bit values.
2. Publishes `<timestamp> <0|1>` through an atomic rename into an immutable per-timestamp file.
3. Waits for the peer file at that exact timestamp.
4. Validates the peer scalar and drives its local input through VPI.
5. Suppresses redundant writes, allowing combinational logic to settle without a delta-cycle loop.
6. Advances using `cbNextSimTime`, then performs the next exchange in `cbReadWriteSynch`.

Replies can therefore reflect one timestep of latency. The integration test checks that explicitly rather than assuming zero-delay combinational communication.

GHDL uses a time divisor of 1000 in the integration configuration, while Icarus uses one, normalizing their timestamps to picoseconds. Both designs must have events at the exchanged timestamps; the Verilog heartbeat provides this schedule.

## Failure and completion behavior

The bridge creates a role-specific `.error` file for invalid configuration, unknown values, malformed peer data, time mismatch, exchange-limit exhaustion, or timeout. A `.done` file is written on normal simulator completion. A waiting peer treats normal completion as a clean stop, not a timeout.

The no-peer test still produces a timeout because no `.done` file exists. This distinction is required for unattended CI use.

VPI immediate-write return handles are not treated as success. Verification comes from independent HDL assertions and clean completion markers; some simulators defer visible updates beyond the callback.

## Reproduction

```bash
TMPDIR=/home/cowboy/ablation \
  python3 /media/cowboy/research/CERN/analysis/mixed-hdl/run_mixed_bridge.py
```

Expected summary:

```json
{
  "status": "PASS",
  "two_way": "PASS",
  "timeout_test": "PASS"
}
```

The runner performs all of the following:

- copies the pinned tools to an executable temporary filesystem;
- compiles the C bridge against both VPI headers with strict warnings;
- analyzes and elaborates the VHDL side;
- compiles the SystemVerilog side;
- runs both simulators concurrently;
- requires both `VERILOG_BRIDGE_PASS` and `VHDL_BRIDGE_PASS`;
- requires both completion markers and no error markers;
- runs GHDL alone and requires a bounded timeout;
- preserves logs and compiled VPI modules under `evidence/`.

`TMPDIR` should name a writable filesystem that permits executable files. Temporary build directories are removed automatically.

## Configuration

The C module reads these environment variables:

| Variable | Meaning |
|---|---|
| `ABLATION_BRIDGE_DIR` | Writable local exchange directory |
| `ABLATION_BRIDGE_ROLE` | `vhdl` or `verilog` |
| `ABLATION_BRIDGE_OUTPUT` | Full hierarchical local output signal |
| `ABLATION_BRIDGE_INPUT` | Full hierarchical local input signal |
| `ABLATION_BRIDGE_TIMEOUT_MS` | Bounded wait, 1–600000 ms |
| `ABLATION_BRIDGE_MAX_STEPS` | Exchange limit, 1–1000000 |
| `ABLATION_BRIDGE_TIME_DIVISOR` | Positive timestamp normalization divisor |

Hierarchical names are resolved at `cbStartOfSimulation`, not during early library loading. The integration uses `vhdl_side.*` and `verilog_side.*` full names.

## Limitations

- One scalar in each direction; there is no packed-vector or record transport yet.
- Matching timestamp events are required; this is not an arbitrary asynchronous protocol.
- Local file exchange is not a network transport and adds no authentication boundary.
- The focused integration is not the complete Endeavour OCB/VHDL testbench.
- The bridge does not provide analog, timing-closure, or electrical models.
- Different simulators may require a different time divisor and VPI object representation.

See [known anomalies](../reference-anomalies/mixed-hdl-vpi-bridge.md), the [SPECS workflow](specs-protocol.md), and the [CERN workflow](../workflows/cern-reverse-engineering-toolchain.md).
