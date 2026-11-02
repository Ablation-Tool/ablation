# CERN Reverse-Engineering and Verification Toolchain

This workflow combines five capabilities built during the CERN analysis: exhaustive SPECS RTL verification, C166 control-flow/xref recovery, bounded C166/CAN execution, mixed VHDL/SystemVerilog simulation, and streaming Xilinx WDB event recovery. It preserves original artifacts and distinguishes static recovery, dynamic models, RTL execution, and hardware evidence.

## Scope and evidence levels

| Level | Meaning in this workflow |
|---|---|
| Static recovery | Instructions, dispatch targets, frame layouts, direct references, and container structure recovered from original artifacts |
| Instruction-level model | Supported C166 instructions execute against explicit memory, register, DPP, and CAN assumptions |
| RTL simulation | Original Verilog or VHDL runs in Icarus/GHDL with focused testbenches |
| Mixed co-simulation | Native VHDL and SystemVerilog run concurrently and exchange VPI scalars |
| Hardware | Not accessed; no CAN frame, FPGA configuration, or deployed update was sent |

A successful result at one level must not be promoted to the next without evidence.

## 1. SPECS exhaustive boundary simulation

### What it does and why it was built

The original SPECS receiver uses `wrdcntreg > 0x80`, while its comment describes long frames in terms of 255. Archived vectors cover only 129 and 130. The simulator supplies all 256 read-count values to the original RTL and dynamically proves the 128/129 boundary and bit-7 output mask.

Two further benefits are independent emitter-inhibit verification and native frame-checksum validation. This closes a specific evidence gap without adding a new abstract protocol model.

### Run

```bash
TMPDIR=/home/cowboy/ablation \
  python3 /media/cowboy/research/CERN/analysis/specs-protocol/run_rtl_boundaries.py
```

Expected: 256 values, 1,280 checks, 127 long-frame cases, and zero checksum errors. Evidence:

- `analysis/specs-protocol/rtl-boundary-findings.json`
- `analysis/specs-protocol/rtl-boundary-sim.log`

Important details:

- Stimulus is serial and includes start/stop, LSB-first data, ninth-bit markers, and valid checksums; internal state is not forced.
- Two build-only instance renames avoid Icarus namespace collisions; logic and original sources are unchanged.
- The third header value is chosen to satisfy both the codec checksum model and the receiver's early third-byte sampling. The discovered sampling difference is documented separately and does not affect count classification.

## 2. C166 recursive CFG and direct xrefs

### What it does and why it was built

`c166_cfg.py` recovers reachable functions and blocks from explicit entries and indexes direct memory accesses. It replaces repeated manual tracing of C166 dispatch chains and searches for state writers such as `0x84FE`, `0x83B9`, and `0x90A6`.

Two further benefits are exclusion of unreachable bytes and conservative DPP-aware data-reference records. Immediate constants and register-indirect accesses are not mislabeled as direct pointers.

### Run the A1396 example

```bash
python3 -m ablation.analyzers.c166_cfg \
  /media/cowboy/research/CERN/analysis/edms-firmware/a1396.bin \
  0x237B2 \
  --xref 0x84FE \
  --output /media/cowboy/research/CERN/analysis/edms-firmware/c166-update-cfg.json
```

Expected recovered points include handlers `0x24792` and `0x24802`, arming write `0x247E6`, gate read `0x24868`, handoff `0x2487A`, and `SRST` at `0x248A4`.

Interpretation cautions:

- Supply additional entries for vectors or computed tables; seeded output is not whole-image proof.
- Unknown instructions remain issues, not invalid-code claims.
- DPP physical addresses require explicit page values.
- Ownership issues around shared tails require review.

## 3. Bounded C166/CAN execution

### What it does and why it was built

`c166_execution.py` runs a supported instruction subset with registers, flags, sparse memory, calls, DPP mappings, direct/indirect accesses, CAN message objects, and bounded traces. It was built to verify arithmetic and state transitions that static disassembly alone could not settle.

Two further benefits are negative-test support and reusable modeling across other C166 CAEN images. Failures are explicit rather than treating unknown instructions or state as successful execution.

### Verified A1396 behavior

The integration starts after receive checksum classification at `0x237B2`. With update state initialized to zero:

1. Valid command `0x06` writes `0x84FE = 7`.
2. Valid or invalid command `0x07` then reaches `SRST` at `0x248A4` and copies `update req` to `0xF800..0xF809`.
3. Invalid command `0x06` follows the `0x247AA` response branch that skips the arming store and leaves `0x84FE` zero.

This corrected the earlier static statement that arm and trigger checksum-failure paths were equivalent. The checksum is still not an authenticity control, and the password flag remains unused.

### Run the tests

```bash
python3 -m pytest -q \
  tests/test_c166_cfg.py \
  tests/test_c166_execution.py \
  tests/test_ecu_c166_decoder.py
```

Expected: 141 passing tests. The model checks DPP-mapped source reads, direct internal-RAM destinations, `ZEROS`/`ONES`, move/zero-extension flag behavior, protected spans, CAN layout, step limits, and exact ten-byte handoff.

Do not treat `SRST` as a hardware reset or as bootloader update acceptance.

## 4. Mixed VHDL/SystemVerilog VPI bridge

### What it does and why it was built

The bridge runs GHDL and Icarus concurrently, exchanges one scalar in each direction through VPI, and checks independent assertions in both languages. It was built because the Endeavour core is Verilog while its host is VHDL; translating the host would weaken the evidence.

Two further benefits are a reusable test of VPI lifecycle/time-unit differences and deterministic completion/timeout handling suitable for CI.

### Run

```bash
TMPDIR=/home/cowboy/ablation \
  python3 /media/cowboy/research/CERN/analysis/mixed-hdl/run_mixed_bridge.py
```

Expected: two-way PASS and timeout-test PASS. Evidence:

- `analysis/mixed-hdl/mixed-bridge-findings.json`
- `analysis/mixed-hdl/evidence/`

The integration validates:

- atomic immutable per-timestamp files;
- settled exchange in `cbReadWriteSynch` after `cbNextSimTime` advancement;
- picosecond normalization (GHDL divisor 1000, Icarus divisor 1);
- matching timestamp schedules driven by the Verilog heartbeat;
- one-timestep inverted reply behavior;
- no false timeout on normal completion;
- a real timeout when GHDL has no peer.

This is a focused two-language integration, not the full Endeavour OCB host. The bridge is scalar-only and is not an arbitrary asynchronous or analog channel.

## 5. Streaming Xilinx WDB recovery

### What it does and why it was built

`xilinx_wdb.py` decodes event pages, zlib chunks, timestamps, root indices, storage IDs, and payloads from legacy WDB 01 files. It was built because the 2017 Endeavour WDB lacks the third section and modern DBG database expected by a newer reader.

Two further benefits are bounded streaming of 10.76 million events and atomic filtered JSONL output. Legacy streams remain unnamed rather than receiving speculative signal assignments.

### Run

```bash
python3 -m ablation.analyzers.xilinx_wdb \
  /media/cowboy/research/CERN/analysis/wdb/endeavour_tb_behav.wdb \
  --events-output /media/cowboy/research/CERN/analysis/wdb/legacy-events.jsonl \
  --summary-output /media/cowboy/research/CERN/analysis/wdb/legacy-summary.json \
  --max-events 16
```

Expected profile facts:

- 21 roots;
- 10,759,544 events;
- first timestamp 0;
- last timestamp 10,030,000,000 ps;
- 16 exported sample events, with `complete_within_limit = false`.

A separately pinned MIT-licensed modern reader is in `analysis/tools/vivado-wdb/`. Its observed 2026.1 profile and full DBG name/type mapping remain distinct from the legacy event-only implementation.

## Verification matrix

| Capability | Synthetic coverage | Original-artifact coverage | Negative coverage |
|---|---|---|---|
| SPECS | Complete frame driver and independent result checks | All 256 receiver count inputs | Wrong long/inhibit/masked counts fail assertions; checksum sampling anomaly isolated |
| C166 CFG | Calls, branches, ownership, xrefs, limits, JSON | A1396 dispatcher and both handlers | Invalid entries, indirect branches, unknown code, exceeded limits |
| C166 execution | Arithmetic, calls, DPP, memory protection, CAN objects | Valid/invalid trigger and invalid arm | Unsupported opcodes, empty stack, protected writes, step limits, bad CAN fields |
| Mixed HDL | Strict C build and two-language assertions | Concurrent GHDL/Icarus two-way exchange | No-peer timeout, time mismatch, malformed values, completion handling |
| Xilinx WDB | Valid container, export filters, bounds | 21 roots and 10,759,544 events | Bad signatures/pointers/zlib/cycles, export and event limits |

## FORGE and delivery requirements

Every new or modified Python module must pass the repository's inline ten-section SAFE CODE audit and `FORGE.audit_module()` before `git add` or commit. Passing tests alone is not a substitute. No commit or push is implied by this workflow.

Required delivery checks include:

1. focused pytest suites;
2. the SPECS and mixed-HDL runners;
3. the full legacy WDB summary/export;
4. documentation and known-anomaly review;
5. `FORGE.audit_module()` cache hits with `gate_passed=True` for every changed Python file;
6. a final working-tree review that separates pre-existing changes from new deliverables and removes temporary outputs.

The complete inline review and cache-verification record is preserved in the [CERN FORGE audit](../forge/cern-toolchain-audit.md).

## Reference guides

- [C166 CFG and xrefs](../reference-modules/c166-cfg.md)
- [Bounded C166 execution](../reference-modules/c166-execution.md)
- [Mixed VPI bridge](../reference-modules/mixed-hdl-vpi-bridge.md)
- [Streaming Xilinx WDB](../reference-modules/xilinx-wdb.md)
- [SPECS protocol](../reference-modules/specs-protocol.md)
- Known anomalies: [CFG](../reference-anomalies/c166-cfg.md), [execution](../reference-anomalies/c166-execution.md), [mixed HDL](../reference-anomalies/mixed-hdl-vpi-bridge.md), [WDB](../reference-anomalies/xilinx-wdb.md)
