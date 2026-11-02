# Known Anomalies: Mixed HDL VPI Bridge

## Scheduling and time

- The bridge requires matching timestamp events in both simulations. Without them, exact peer files cannot be produced and a timeout is expected.
- `cbNextSimTime` can run before a timestep's new values settle. The implementation therefore advances with it but exchanges in `cbReadWriteSynch`.
- Re-registering only `cbReadWriteSynch` can loop on Icarus. The two-phase scheduler is required.
- GHDL and Icarus can report different time units. A wrong `ABLATION_BRIDGE_TIME_DIVISOR` creates timestamp mismatches; the integration uses 1000 for GHDL and one for Icarus.

## VPI object behavior

- Early signal lookup during VPI library loading can fail or crash GHDL. Signals are resolved at `cbStartOfSimulation` with full hierarchical names.
- GHDL rejects `vpiStringVal` for scalar `std_logic`. Values are read with `vpiIntVal` and restricted to 0/1.
- A null `vpi_put_value` handle is not a reliable failure indicator, and immediate readback can precede visible settlement. End-to-end HDL assertions are the acceptance oracle.
- Redundant identical writes are suppressed to avoid unnecessary events; changed combinational values are still exchanged at subsequent settled timestamps.

## Transport and coverage

- Only one scalar per direction is supported. Vectors, records, drives with X/Z semantics, and multiple independent channels require a new validated transport profile.
- Per-timestamp files grow with the number of exchanges. The runner uses bounded temporary directories and removes them afterward; long-running users need their own retention policy.
- File exchange is local and unauthenticated. Do not place exchange directories on an untrusted shared filesystem.
- The focused two-way test does not establish that the complete Endeavour OCB host works. That integration needs its vendor models, reset behavior, and protocol assertions.

## Failure handling

- `.done` distinguishes normal peer completion from a true missing peer. Deleting it changes shutdown semantics and can produce misleading timeout errors.
- Runner timeouts terminate only child simulator processes started by the runner. Temporary VPI evidence is retained separately in `evidence/`.
